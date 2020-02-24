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

        class ThreadInfo
        {
            public bool Active;
            public long ReportId;
            public double TotalTime;
            public double StartTime;
        }

        #endregion Classes

        #region Methods

        static void Main(string[] args)
        {
            Process.EnterDebugMode();

            var influxAddress = args[0];
            var appName = args[1];

            var appProcess = Process.GetProcesses().FirstOrDefault(x => x.ProcessName == appName);
            var appPid = appProcess?.Id ?? FORBIDDEN_ID;
            if (appPid != FORBIDDEN_ID)
                Console.WriteLine("Process {0} started, new pid {1}", appName, appPid);

            long writeBytes = 0;
            long writeCalls = 0;
            long readBytes = 0;
            long readCalls = 0;

            long tcpSentBytes = 0;
            long tcpSentPackets = 0;
            long tcpRecvBytes = 0;
            long tcpRecvPackets = 0;

            long udpSentBytes = 0;
            long udpSentPackets = 0;
            long udpRecvBytes = 0;
            long udpRecvPackets = 0;

            long threadsCount = 0;
            long handlesCount = 0;
            long workingSet = 0;
            long privateMemorySize = 0;

            var nextReport = Environment.TickCount + REP_INTERVAL;
            var reportId = 0;

            var concurrency = new double[Environment.ProcessorCount + 1];
            var concurrencyLast = 0.0;
            var concurrencyCounter = 0;
            var threads = new Dictionary<int, ThreadInfo>();

            var collector = new CollectorConfiguration()
                .Tag.With("host", Environment.GetEnvironmentVariable("COMPUTERNAME"))
                .Tag.With("app", appName)
                .Batch.AtInterval(TimeSpan.FromSeconds(5))
                .WriteTo.InfluxDB(influxAddress, DB_NAME)
                .CreateCollector();

            // ETW works quite unstable for PerformanceCounters and MemInfo events, so get them through good old API
            var apiTimer = new Timer(state =>
            {
                try
                {
                    if (appPid == FORBIDDEN_ID)
                        return;

                    if (appProcess == null || appProcess.Id != appPid)
                        appProcess = Process.GetProcessById(appPid);

                    appProcess.Refresh();
                    threadsCount = appProcess.Threads.Count;
                    handlesCount = appProcess.HandleCount;
                    workingSet = appProcess.WorkingSet64;
                    privateMemorySize = appProcess.PrivateMemorySize64;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
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

                void SwitchOn(int threadId, double timestamp)
                {
                    concurrency[concurrencyCounter] += timestamp - concurrencyLast;
                    concurrencyLast = timestamp;
                    concurrencyCounter += 1;

                    if (!threads.TryGetValue(threadId, out var info))
                    {
                        info = new ThreadInfo();
                        threads[threadId] = info;
                    }

                    info.Active = true;
                    info.StartTime = timestamp;
                    info.ReportId = reportId;
                }

                void SwitchOff(int threadId, double timestamp)
                {
                    concurrency[concurrencyCounter] += timestamp - concurrencyLast;
                    concurrencyLast = timestamp;
                    concurrencyCounter = concurrencyCounter + (-concurrencyCounter >> 31);

                    if (threads.TryGetValue(threadId, out var info))
                    {
                        if (info.Active)
                            info.TotalTime += timestamp - info.StartTime;
                        info.Active = false;
                    }
                }

                session.Source.Kernel.ProcessStart += e =>
                {
                    if (e.ProcessName != appName)
                        return;

                    appPid = e.ProcessID;
                    Console.WriteLine("Process {0} started, new pid {1}", appName, appPid);
                };

                session.Source.Kernel.ProcessStop += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    appPid = FORBIDDEN_ID;
                    Console.WriteLine("Process {0} stopped, old pid {1}", appName, e.ProcessID);

                    threads.Clear();
                    Array.Clear(concurrency, 0, concurrency.Length);
                    concurrencyCounter = 0;
                };

                session.Source.Kernel.ThreadStart += e =>
                {
                };

                session.Source.Kernel.ThreadStop += e =>
                {
                    if (e.ProcessID == appPid)
                        SwitchOff(e.ThreadID, e.TimeStampRelativeMSec);
                    threads.Remove(e.ThreadID);
                };

                session.Source.Kernel.ProcessPerfCtr += e =>
                {
                    Console.WriteLine(e.ToString());
                };

                session.Source.Kernel.ProcessPerfCtrRundown += e =>
                {
                    Console.WriteLine(e.ToString());
                };

                session.Source.Kernel.FileIORead += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    readBytes += e.IoSize;
                    readCalls += 1;
                };

                session.Source.Kernel.FileIOWrite += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    writeBytes += e.IoSize;
                    writeCalls += 1;
                };

                session.Source.Kernel.TcpIpRecv += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    tcpRecvBytes += e.size;
                    tcpRecvPackets += 1;
                };

                session.Source.Kernel.TcpIpSend += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    tcpSentBytes += e.size;
                    tcpSentPackets += 1;
                };

                session.Source.Kernel.UdpIpRecv += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    udpRecvBytes += e.size;
                    udpRecvPackets += 1;
                };

                session.Source.Kernel.UdpIpSend += e =>
                {
                    if (e.ProcessID != appPid)
                        return;

                    udpSentBytes += e.size;
                    udpSentPackets += 1;
                };

                session.Source.Kernel.ThreadCSwitch += e =>
                {
                    if (e.ProcessID != appPid && e.OldProcessID != appPid)
                        return;

                    if (e.OldProcessID == appPid)
                        SwitchOff(e.OldThreadID, e.TimeStampRelativeMSec);
                    if (e.ProcessID == appPid)
                        SwitchOn(e.ThreadID, e.TimeStampRelativeMSec);

                    if (Environment.TickCount > nextReport)
                    {
                        var metrics = new Dictionary<string, object>
                        {
                            ["write_bytes"] = TakeAndReset(ref writeBytes),
                            ["write_calls"] = TakeAndReset(ref writeCalls),
                            ["read_bytes"] = TakeAndReset(ref readBytes),
                            ["read_calls"] = TakeAndReset(ref readCalls),

                            ["tcp_sent_bytes"] = TakeAndReset(ref tcpSentBytes),
                            ["tcp_sent_packets"] = TakeAndReset(ref tcpSentPackets),
                            ["tcp_recv_bytes"] = TakeAndReset(ref tcpRecvBytes),
                            ["tcp_recv_packets"] = TakeAndReset(ref tcpRecvPackets),

                            ["udp_sent_bytes"] = TakeAndReset(ref udpSentBytes),
                            ["udp_sent_packets"] = TakeAndReset(ref udpSentPackets),
                            ["udp_recv_bytes"] = TakeAndReset(ref udpRecvBytes),
                            ["udp_recv_packets"] = TakeAndReset(ref udpRecvPackets)
                        };

                        // CPU Statistics
                        var procTimeTotal = 0.0;
                        var procTimeTotalAnti = 0.0;
                        for (var i = 1; i < concurrency.Length; ++i)
                        {
                            procTimeTotal += i * concurrency[i];
                            procTimeTotalAnti += concurrency[i];
                            metrics[$"cpu_{i}"] = concurrency[i] / REP_INTERVAL * 100;
                        }
                        metrics["cpu_ratio"] = procTimeTotal / REP_INTERVAL / Environment.ProcessorCount * 100;
                        metrics["cpu_antiratio"] = procTimeTotalAnti / REP_INTERVAL  * 100;
                        Array.Clear(concurrency, 0, concurrency.Length);

                        // Thread Statistics
                        var threadMin = double.PositiveInfinity;
                        var threadMax = 0.0;
                        var count = 0;
                        var active = 0;

                        var deadThreads = new HashSet<int>();
                        foreach (var entry in threads)
                        {
                            // Sometimes ETW can skip events, so add bunch of crutches to handle it
                            if (reportId >= entry.Value.ReportId + DEAD_THRESHOLD)
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
                            threads.Remove(entry);

                        metrics["threads_count"] = threadsCount;
                        metrics["threads_active"] = active;
                        metrics["threads_dur_min"] = !double.IsPositiveInfinity(threadMin) ? threadMin : 0.0;
                        metrics["threads_dur_aver"] = procTimeTotal / active;
                        metrics["threads_dur_max"] = threadMax;

                        metrics["handles"] = handlesCount;
                        metrics["working_set"] = workingSet;
                        metrics["private_memory_size"] = privateMemorySize;

                        collector.Write(DB_NAME, metrics);

                        reportId += 1;
                        nextReport += REP_INTERVAL;
                    }
                };

                session.Source.Process();
            }
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