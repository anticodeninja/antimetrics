// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

namespace Antimetrics
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Threading;
    using InfluxDB.Collector;
    using Microsoft.Diagnostics.Tracing.Parsers;
    using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
    using Microsoft.Diagnostics.Tracing.Session;

    class Program
    {
        #region Constants

        private const int FORBIDDEN_ID = -1;

        private const int REP_INTERVAL = 1000;

        private const int DEAD_THRESHOLD = 10;

        const double TOLERANCE = 0.0001;

        private const string DB_NAME = "antimetrics";

        #endregion Constants

        #region Classes

        class ProcessState
        {
            public string Name;

            public int Pid;

            public Process Process;

            public MetricsCollector Collector;

            public double[] Concurrency;
            public double ConcurrencyLast;
            public int ConcurrencyCounter;
            public Dictionary<int, ThreadState> Threads;

            public long WriteBytes;
            public long WriteCalls;
            public long ReadBytes;
            public long ReadCalls;

            public long TcpSentBytes;
            public long TcpSentPackets;
            public long TcpRecvBytes;
            public long TcpRecvPackets;

            public long UdpSentBytes;
            public long UdpSentPackets;
            public long UdpRecvBytes;
            public long UdpRecvPackets;

            public long ThreadsCount;
            public long HandlesCount;
            public long WorkingSet;
            public long PrivateMemorySize;
        }

        class ThreadState
        {
            public bool Active;
            public long ReportId;
            public double TotalTime;
            public double StartTime;
        }

        #endregion Classes

        #region Fields

        private readonly string _influxAddress;

        private readonly Dictionary<string, ProcessState> _monitoredProcesses;

        private readonly Dictionary<int, ProcessState> _activeProcesses;

        private long _nextReport;

        private int _reportId;

        #endregion Fields

        #region Constructors

        private Program(string[] args)
        {
            _influxAddress = args[0];

            _monitoredProcesses = new Dictionary<string, ProcessState>();
            for (var i = 1; i < args.Length; ++i)
            {
                _monitoredProcesses[args[i]] = new ProcessState()
                {
                    Pid = FORBIDDEN_ID,
                    Name = args[i],
                };
            }
            _activeProcesses = new Dictionary<int, ProcessState>();
        }

        #endregion Constructors

        #region Methods

        static void Main(string[] args) => new Program(args).Run();

        void Run()
        {
            Process.EnterDebugMode();

            foreach (var process in _monitoredProcesses.Values)
            {
                process.Concurrency = new double[Environment.ProcessorCount + 1];
                process.ConcurrencyLast = 0.0;
                process.ConcurrencyCounter = 0;
                process.Threads = new Dictionary<int, ThreadState>();

                process.Collector = new CollectorConfiguration()
                    .Tag.With("host", Environment.GetEnvironmentVariable("COMPUTERNAME"))
                    .Tag.With("app", process.Name)
                    .Batch.AtInterval(TimeSpan.FromSeconds(5))
                    .WriteTo.InfluxDB(_influxAddress, DB_NAME)
                    .CreateCollector();

                process.Process = Process.GetProcesses().FirstOrDefault(x => x.ProcessName == process.Name);
                if (process.Process != null)
                {
                    process.Pid = process.Process.Id;
                    _activeProcesses[process.Pid] = process;
                    Console.WriteLine("Process {0} is already active, pid {1}", process.Name, process.Pid);
                }
            }

            _nextReport = Environment.TickCount + REP_INTERVAL;
            _reportId = 0;

            // ETW works quite unstable for PerformanceCounters and MemInfo events, so get them through good old API
            var apiTimer = new Timer(state =>
            {
                foreach (var process in _monitoredProcesses.Values)
                {
                    try
                    {
                        if (process.Pid == FORBIDDEN_ID)
                            continue;

                        if (process.Process == null || process.Process.Id != process.Pid)
                            process.Process = Process.GetProcessById(process.Pid);

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
            }, null, 0, REP_INTERVAL);

            using (var session = new TraceEventSession("antimetrics"))
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process |
                                             KernelTraceEventParser.Keywords.Thread |
                                             KernelTraceEventParser.Keywords.NetworkTCPIP |
                                             KernelTraceEventParser.Keywords.Dispatcher |
                                             KernelTraceEventParser.Keywords.ContextSwitch |
                                             KernelTraceEventParser.Keywords.FileIOInit);

                void SwitchOn(ProcessState process, int threadId, double timestamp)
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

                void SwitchOff(ProcessState process, int threadId, double timestamp)
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

                session.Source.Kernel.ProcessStart += e =>
                {
                    if (!_monitoredProcesses.TryGetValue(e.ProcessName, out var process))
                        return;

                    process.Pid = e.ProcessID;
                    _activeProcesses[process.Pid] = process;
                    Console.WriteLine("Process {0} started, new pid {1}", process.Name, e.ProcessID);
                };

                session.Source.Kernel.ProcessStop += e =>
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

                session.Source.Kernel.ThreadStart += e =>
                {
                };

                session.Source.Kernel.ThreadStop += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    SwitchOff(process, e.ThreadID, e.TimeStampRelativeMSec);
                    process.Threads.Remove(e.ThreadID);
                };

                session.Source.Kernel.FileIORead += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.ReadBytes += e.IoSize;
                    process.ReadCalls += 1;
                };

                session.Source.Kernel.FileIOWrite += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.WriteBytes += e.IoSize;
                    process.WriteCalls += 1;
                };

                session.Source.Kernel.TcpIpRecv += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.TcpRecvBytes += e.size;
                    process.TcpRecvPackets += 1;
                };

                session.Source.Kernel.TcpIpSend += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.TcpSentBytes += e.size;
                    process.TcpSentPackets += 1;
                };

                session.Source.Kernel.UdpIpRecv += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.UdpRecvBytes += e.size;
                    process.UdpRecvPackets += 1;
                };

                session.Source.Kernel.UdpIpSend += e =>
                {
                    if (!_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        return;

                    process.UdpSentBytes += e.size;
                    process.UdpSentPackets += 1;
                };

                session.Source.Kernel.ThreadCSwitch += e =>
                {
                    if (_activeProcesses.TryGetValue(e.OldProcessID, out var oldProcess))
                        SwitchOff(oldProcess, e.OldThreadID, e.TimeStampRelativeMSec);
                    if (_activeProcesses.TryGetValue(e.ProcessID, out var process))
                        SwitchOn(process, e.ThreadID, e.TimeStampRelativeMSec);

                    if (Environment.TickCount > _nextReport)
                        GenerateReport(e);
                };

                session.Source.Process();
            }
        }

        private void GenerateReport(CSwitchTraceData e)
        {
            foreach (var process in _monitoredProcesses.Values)
            {
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
                var procTimeTotal = 0.0;
                var procTimeTotalAnti = 0.0;
                for (var i = 1; i < process.Concurrency.Length; ++i)
                {
                    procTimeTotal += i * process.Concurrency[i];
                    procTimeTotalAnti += process.Concurrency[i];
                    metrics[$"cpu_{i}"] = process.Concurrency[i] / REP_INTERVAL * 100;
                }

                metrics["cpu_ratio"] = procTimeTotal / REP_INTERVAL / Environment.ProcessorCount * 100;
                metrics["cpu_antiratio"] = procTimeTotalAnti / REP_INTERVAL * 100;
                Array.Clear(process.Concurrency, 0, process.Concurrency.Length);

                // Thread Statistics
                var threadMin = double.PositiveInfinity;
                var threadMax = 0.0;
                var count = 0;
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
                        entry.Value.TotalTime += e.TimeStampRelativeMSec - entry.Value.StartTime;
                        entry.Value.StartTime = e.TimeStampRelativeMSec;
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
                    process.Threads.Remove(entry);

                metrics["threads_count"] = process.ThreadsCount;
                metrics["threads_active"] = active;
                metrics["threads_dur_min"] = !double.IsPositiveInfinity(threadMin) ? threadMin : 0.0;
                metrics["threads_dur_aver"] = procTimeTotal / active;
                metrics["threads_dur_max"] = threadMax;

                metrics["handles"] = process.HandlesCount;
                metrics["working_set"] = process.WorkingSet;
                metrics["private_memory_size"] = process.PrivateMemorySize;

                process.Collector.Write(DB_NAME, metrics);
            }

            _reportId += 1;
            _nextReport += REP_INTERVAL;
        }

        private static long TakeAndReset(ref long metric)
        {
            var temp = metric;
            metric = 0;
            return temp;
        }

        #endregion Methods
    }
}