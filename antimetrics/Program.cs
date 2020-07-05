// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

namespace Antimetrics
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Runtime.InteropServices;
    using System.Threading;
    using AntiFramework.Utils;
    using InfluxDB.Collector;
    using InfluxDB.Collector.Diagnostics;
    using Microsoft.Diagnostics.Tracing.Parsers;
    using Microsoft.Diagnostics.Tracing.Session;

    class Program
    {
        #region Constants

        private const int FORBIDDEN_ID = -1;

        private const int REP_INTERVAL = 1000;

        private const int DOUBLE_PRECISION = 1000;

        private const int DEAD_THRESHOLD = 10;

        const double TOLERANCE = 0.0001;

        private const string DB_NAME = "antimetrics";

        #endregion Constants

        #region Classes

        #endregion Classes

        #region Fields

        private readonly Dictionary<string, ProcessState> _monitoredProcesses;

        private readonly Dictionary<int, ProcessState> _activeProcesses;

        private int _verbose;

        private TraceEventSession _session;
        private long _lastSwitchReport;

        private long _nextReport;
        private int _reportId;

        private string _dumpsDirectory;

        private bool _active;

        #endregion Fields

        #region Constructors

        private Program()
        {
            _monitoredProcesses = new Dictionary<string, ProcessState>();
            _activeProcesses = new Dictionary<int, ProcessState>();
        }

        #endregion Constructors

        #region Methods

        static void Main(string[] args) => new Program().Run(args);

        void Run(string[] args)
        {
            AppDomain.CurrentDomain.ProcessExit += (sender, eventArgs) => _active = false;
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                _active = false;
            };

            var result = new ArgsParser(args)
                .Help("?", "help")
                .Comment("antimetrics is an application for a process health metrics collection (like cpu and memory consumptions) via API and ETW\n" +
                         "counters and publishing them into an database for further analyses.")
                .Keys("v", "verbose").Tip("increase output verbosity").Flag(out _verbose)
                .Keys("no-proxy").Tip("disable proxy usage").Flag(out var noProxy)
                .Keys("with-influx").Tip("enable influx usage and set its address (ex. http://127.0.0.1:8086)").Value<string>(out var influxAddress, null)
                .Keys("with-dumps").Tip("enable auto dumping and set its directory (ex. C:\\dumps)").Value<string>(out _dumpsDirectory, null)
                .Name("process").Amount(1, int.MaxValue).Tip("list of process names for monitoring").Values<string>(out var processes)
                .Result();

            if (result != null)
            {
                Console.WriteLine(result);
                return;
            }

            if (noProxy > 0)
                HttpClient.DefaultProxy = new DisableSystemProxy();
            CollectorLog.RegisterErrorHandler((message, exception) =>
            {
                if (_verbose >= 1)
                    Console.WriteLine($"{message}: {exception}");
            });

            for (var i = 0; i < processes.Count; ++i)
            {
                if (FindProcessByPid(processes[i], out var process))
                {
                    _monitoredProcesses[processes[i]] = new ProcessState
                    {
                        Pid = process.Id,
                        Name = process.ProcessName,
                        Process = process,
                    };
                }
                else
                {
                    _monitoredProcesses[processes[i]] = new ProcessState
                    {
                        Pid = FORBIDDEN_ID,
                        Name = processes[i],
                    };
                }
            }

            foreach (var process in _monitoredProcesses.Values)
            {
                process.Concurrency = new long[Environment.ProcessorCount + 1];
                process.ConcurrencyLast = 0;
                process.ConcurrencyCounter = 0;
                process.Threads = new ConcurrentDictionary<int, ThreadState>();

                if (influxAddress != null)
                {
                    process.Collector = new CollectorConfiguration()
                        .Tag.With("host", Environment.GetEnvironmentVariable("COMPUTERNAME"))
                        .Tag.With("app", process.Name)
                        .Batch.AtInterval(TimeSpan.FromSeconds(5))
                        .WriteTo.InfluxDB(influxAddress, DB_NAME)
                        .CreateCollector();
                }

                process.Process ??= Process.GetProcesses().FirstOrDefault(x => x.ProcessName == process.Name);
                if (process.Process != null)
                {
                    Console.WriteLine("Process {0} is already active, pid {1}", process.Name, process.Process.Id);
                    process.Pid = process.Process.Id;
                    _activeProcesses[process.Pid] = process;
                }
                else
                {
                    Console.WriteLine("Process {0} is not found, waiting...", process.Name);
                }
            }

            _nextReport = Environment.TickCount64 + REP_INTERVAL;
            _reportId = 0;

            _active = true;
            // ETW works quite unstable for PerformanceCounters and MemInfo events, so get them through good old API
            var apiCollector = new Thread(ApiCollector)
            {
                Name = "API Collector"
            };
            apiCollector.Start();

            var etwCollector = new Thread(EtwCollector)
            {
                Name = "ETW Collector"
            };
            etwCollector.Start();

            MainWorker();

            _session.Stop();
            apiCollector.Join();
            etwCollector.Join();
        }

        private void EtwCollector()
        {
            using (_session = new TraceEventSession("antimetrics"))
            {
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process |
                                             KernelTraceEventParser.Keywords.Thread |
                                             KernelTraceEventParser.Keywords.NetworkTCPIP |
                                             KernelTraceEventParser.Keywords.Dispatcher |
                                             KernelTraceEventParser.Keywords.ContextSwitch |
                                             KernelTraceEventParser.Keywords.FileIOInit);

                void SwitchOn(ProcessState process, int threadId, long timestamp)
                {
                    process.Concurrency[process.ConcurrencyCounter] += timestamp - process.ConcurrencyLast;
                    process.ConcurrencyLast = timestamp;
                    process.ConcurrencyCounter += 1;

                    if (!process.Threads.TryGetValue(threadId, out var thread))
                    {
                        thread = new ThreadState();
                        process.Threads[threadId] = thread;
                    }

                    thread.Active = true;
                    thread.StartTime = timestamp;
                    thread.ReportId = _reportId;
                }

                void SwitchOff(ProcessState process, int threadId, long timestamp)
                {
                    process.Concurrency[process.ConcurrencyCounter] += timestamp - process.ConcurrencyLast;
                    process.ConcurrencyLast = timestamp;
                    process.ConcurrencyCounter = process.ConcurrencyCounter + (-process.ConcurrencyCounter >> 31);

                    if (process.Threads.TryGetValue(threadId, out var info))
                    {
                        if (info.Active)
                            info.TotalTime += timestamp - info.StartTime;
                        info.Active = false;
                    }
                }

                _session.Source.Kernel.ProcessStart += e =>
                {
                    if (!_monitoredProcesses.TryGetValue(e.ProcessName, out var process))
                        return;

                    process.Pid = e.ProcessID;
                    _activeProcesses[process.Pid] = process;
                    Console.WriteLine("Process {0} started, new pid {1}", process.Name, e.ProcessID);
                };

                _session.Source.Kernel.ProcessStop += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.Pid = FORBIDDEN_ID;
                    _activeProcesses.Remove(e.ProcessID);
                    Console.WriteLine("Process {0} stopped, old pid {1}", process.Name, e.ProcessID);

                    process.Threads.Clear();
                    Array.Clear(process.Concurrency, 0, process.Concurrency.Length);
                    process.ConcurrencyCounter = 0;
                };

                _session.Source.Kernel.ThreadStart += e => { };

                _session.Source.Kernel.ThreadStop += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    var timestamp = (long)(e.TimeStampRelativeMSec * DOUBLE_PRECISION);
                    SwitchOff(process, e.ThreadID, timestamp);
                    process.Threads.Remove(e.ThreadID, out _);
                };

                _session.Source.Kernel.FileIORead += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.ReadBytes += e.IoSize;
                    process.ReadCalls += 1;
                };

                _session.Source.Kernel.FileIOWrite += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.WriteBytes += e.IoSize;
                    process.WriteCalls += 1;
                };

                _session.Source.Kernel.TcpIpRecv += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.TcpRecvBytes += e.size;
                    process.TcpRecvPackets += 1;
                };

                _session.Source.Kernel.TcpIpSend += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.TcpSentBytes += e.size;
                    process.TcpSentPackets += 1;
                };

                _session.Source.Kernel.UdpIpRecv += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.UdpRecvBytes += e.size;
                    process.UdpRecvPackets += 1;
                };

                _session.Source.Kernel.UdpIpSend += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.UdpSentBytes += e.size;
                    process.UdpSentPackets += 1;
                };

                _session.Source.Kernel.ThreadCSwitch += e =>
                {
                    var timestamp = (long)(e.TimeStampRelativeMSec * DOUBLE_PRECISION);
                    if (_activeProcesses.TryGetValue(e.OldProcessID, out var oldProcess))
                        SwitchOff(oldProcess, e.OldThreadID, timestamp);
                    if (_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        SwitchOn(process, e.ThreadID, timestamp);
                    Interlocked.Exchange(ref _lastSwitchReport, timestamp);
                };

                _session.Source.Process();
            }
        }

        private void ApiCollector()
        {
            while (_active)
            {
                foreach (var process in _monitoredProcesses.Values)
                {
                    try
                    {
                        if (process.Pid == FORBIDDEN_ID)
                            continue;

                        if ((process.Process == null || process.Process.Id != process.Pid) && !FindProcessByPid(process.Pid, out process.Process))
                            continue;

                        if (_dumpsDirectory != null && (process.Debugger == null || process.Debugger.HasExited))
                        {
                            var exeName = $"antidbg.{(Is64Bit(process.Process) ? "x64" : "x86")}.exe";
                            var exePath = Path.Join(AppContext.BaseDirectory, exeName);

                            process.Debugger = Process.Start(new ProcessStartInfo(exePath, $"{process.Pid} \"path {_dumpsDirectory}\"")
                            {
                                RedirectStandardInput = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                            });

                            process.Debugger.OutputDataReceived += DebuggerOnOutputDataReceived;
                            process.Debugger.BeginOutputReadLine();
                        }

                        process.Process.Refresh();

                        process.ThreadsCount = process.Process.Threads.Count;
                        process.HandlesCount = process.Process.HandleCount;
                        process.WorkingSet = process.Process.WorkingSet64;
                        process.PrivateMemorySize = process.Process.PrivateMemorySize64;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }

                Thread.Sleep(REP_INTERVAL);
            }
        }

        private void DebuggerOnOutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (_verbose >= 1)
                Console.WriteLine(e.Data);
        }

        private void MainWorker()
        {
            while (_active)
            {
                var delta = _nextReport - Environment.TickCount64;
                if (delta > REP_INTERVAL)
                    _nextReport = Environment.TickCount64;
                else if (delta > 0)
                    Thread.Sleep((int) delta);
                _nextReport += REP_INTERVAL;

                foreach (var process in _monitoredProcesses.Values)
                {
                    if (process.Process == null)
                        continue;

                    var metrics = new Dictionary<string, object>
                    {
                        ["write_bytes"] = TakeAndReset(ref process.WriteBytes),
                        ["write_calls"] = TakeAndReset(ref process.WriteCalls),
                        ["read_bytes"] = TakeAndReset(ref process.ReadBytes),
                        ["read_calls"] = TakeAndReset(ref process.ReadCalls),
                        ["tcp_sent_bytes"] = TakeAndReset(ref process.TcpSentBytes),
                        ["tcp_sent_packets"] = TakeAndReset(ref process.TcpSentPackets),
                        ["tcp_recv_bytes"] = TakeAndReset(ref process.TcpRecvBytes),
                        ["tcp_recv_packets"] = TakeAndReset(ref process.TcpRecvPackets),
                        ["udp_sent_bytes"] = TakeAndReset(ref process.UdpSentBytes),
                        ["udp_sent_packets"] = TakeAndReset(ref process.UdpSentPackets),
                        ["udp_recv_bytes"] = TakeAndReset(ref process.UdpRecvBytes),
                        ["udp_recv_packets"] = TakeAndReset(ref process.UdpRecvPackets)
                    };

                    // CPU Statistics
                    var procTimeTotal = 0L;
                    var procTimeTotalAnti = 0L;
                    for (var i = 1; i < process.Concurrency.Length; ++i)
                    {
                        procTimeTotal += i * process.Concurrency[i];
                        procTimeTotalAnti += process.Concurrency[i];
                        metrics[$"cpu_{i}"] = (double) process.Concurrency[i] / DOUBLE_PRECISION / REP_INTERVAL * 100;
                    }

                    metrics["cpu_ratio"] = (double) procTimeTotal / DOUBLE_PRECISION / REP_INTERVAL / Environment.ProcessorCount * 100;
                    metrics["cpu_antiratio"] = (double) procTimeTotalAnti / DOUBLE_PRECISION / REP_INTERVAL * 100;
                    Array.Clear(process.Concurrency, 0, process.Concurrency.Length);

                    // Thread Statistics
                    var threadMin = double.PositiveInfinity;
                    var threadMax = 0.0;
                    var active = 0;

                    var deadThreads = new HashSet<int>();
                    foreach (var entry in process.Threads)
                    {
                        // Sometimes ETW can skip events, so add bunch of crutches to handle it
                        if (_reportId >= entry.Value.ReportId + DEAD_THRESHOLD)
                        {
                            deadThreads.Add(entry.Key);
                            continue;
                        }

                        if (entry.Value.Active)
                        {
                            entry.Value.TotalTime += _lastSwitchReport - entry.Value.StartTime;
                            entry.Value.StartTime = _lastSwitchReport;
                        }

                        if (entry.Value.TotalTime > TOLERANCE)
                        {
                            threadMin = Math.Min(threadMin, entry.Value.TotalTime);
                            threadMax = Math.Max(threadMax, entry.Value.TotalTime);
                            active += 1;
                        }

                        entry.Value.TotalTime = 0.0;
                    }

                    foreach (var entry in deadThreads)
                        process.Threads.Remove(entry, out _);

                    metrics["threads_count"] = process.ThreadsCount;
                    metrics["threads_active"] = active;
                    metrics["threads_dur_min"] = !double.IsPositiveInfinity(threadMin) ? threadMin : 0.0;
                    metrics["threads_dur_aver"] = active > 0 ? (double) procTimeTotal / DOUBLE_PRECISION / active : 0.0;
                    metrics["threads_dur_max"] = threadMax;

                    metrics["handles"] = process.HandlesCount;
                    metrics["working_set"] = process.WorkingSet;
                    metrics["private_memory_size"] = process.PrivateMemorySize;

                    if (_verbose >= 2)
                        Console.WriteLine(string.Join(",", metrics.Select(kv => kv.Key + "=" + kv.Value)));

                    process.Collector?.Write(DB_NAME, metrics);
                }

                _reportId += 1;
            }
        }

        private static long TakeAndReset(ref long metric)
        {
            var temp = metric;
            metric = 0;
            return temp;
        }

        private static bool FindProcessByPid(string pid, out Process process)
        {
            process = null;
            if (!int.TryParse(pid, out var value))
                return  false;

            return FindProcessByPid(value, out process);
        }

        private static bool FindProcessByPid(int pid, out Process process)
        {
            process = null;

            try
            {
                process = Process.GetProcessById(pid);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool Is64Bit(Process process)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!IsWow64Process(process.Handle, out bool isWow64))
                return false;

            return !isWow64;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        #endregion Methods
    }
}
