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

    using InfluxDB.Collector;
    using Microsoft.Diagnostics.Tracing.Parsers;
    using Microsoft.Diagnostics.Tracing.Session;

    class Program
    {
        #region Constants

        private const int REP_INTERVAL = 1000;

        private const string DB_NAME = "antimetrics";

        #endregion Constants

        #region Methods

        static void Main(string[] args)
        {
            Process.EnterDebugMode();

            var influxAddress = args[0];
            var appName = args[1];

            long TakeAndReset(ref long metric)
            {
                var temp = metric;
                metric = 0;
                return temp;
            }

            var serverProcess = Process.GetProcesses().FirstOrDefault(x => x.ProcessName == appName);
            if (serverProcess == null)
                return;
            var serverPid = serverProcess.Id;

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

            var nextReport = Environment.TickCount + REP_INTERVAL;

            var concurrency = new double[Environment.ProcessorCount + 1];
            var concurrencyLast = 0.0;
            var concurrencyCounter = 0;

            var collector = new CollectorConfiguration()
                .Tag.With("host", Environment.GetEnvironmentVariable("COMPUTERNAME"))
                .Tag.With("app", appName)
                .Batch.AtInterval(TimeSpan.FromSeconds(5))
                .WriteTo.InfluxDB(influxAddress, DB_NAME)
                .CreateCollector();

            using (var session = new TraceEventSession("MySimpleSession")) {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Thread |
                                             KernelTraceEventParser.Keywords.ThreadTime |
                                             KernelTraceEventParser.Keywords.FileIOInit |
                                             KernelTraceEventParser.Keywords.NetworkTCPIP);

                void SwitchOn(double timestamp)
                {
                    concurrency[concurrencyCounter] += timestamp - concurrencyLast;
                    concurrencyLast = timestamp;
                    concurrencyCounter += 1;
                }

                void SwitchOff(double timestamp)
                {
                    concurrency[concurrencyCounter] += timestamp - concurrencyLast;
                    concurrencyLast = timestamp;
                    concurrencyCounter = concurrencyCounter + (-concurrencyCounter >> 31);
                }

                session.Source.Kernel.ThreadStart += e =>
                {
                };

                session.Source.Kernel.ThreadStop += e =>
                {
                    if (e.ProcessID == serverPid)
                        SwitchOff(e.TimeStampRelativeMSec);
                };

                session.Source.Kernel.FileIORead += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    readBytes += e.IoSize;
                    readCalls += 1;
                };

                session.Source.Kernel.FileIOWrite += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    writeBytes += e.IoSize;
                    writeCalls += 1;
                };

                session.Source.Kernel.TcpIpRecv += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    tcpRecvBytes += e.size;
                    tcpRecvPackets += 1;
                };

                session.Source.Kernel.TcpIpSend += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    tcpSentBytes += e.size;
                    tcpSentPackets += 1;
                };

                session.Source.Kernel.UdpIpRecv += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    udpRecvBytes += e.size;
                    udpRecvPackets += 1;
                };

                session.Source.Kernel.UdpIpSend += e =>
                {
                    if (e.ProcessID != serverPid)
                        return;

                    udpSentBytes += e.size;
                    udpSentPackets += 1;
                };

                session.Source.Kernel.ThreadCSwitch += e =>
                {
                    if (e.ProcessID != serverPid && e.OldProcessID != serverPid)
                        return;

                    if (e.OldProcessID == serverPid)
                        SwitchOff(e.TimeStampRelativeMSec);
                    if (e.ProcessID == serverPid)
                        SwitchOn(e.TimeStampRelativeMSec);

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

                        var procTimeTotal = 0.0;
                        var procTimeTotalAnti = 0.0;
                        for (var i = 1; i < concurrency.Length; ++i)
                        {
                            procTimeTotal += i * concurrency[i];
                            procTimeTotalAnti += concurrency[i];
                            metrics[$"cpu_{i}"] = concurrency[i] / REP_INTERVAL * 100;
                        }
                        metrics["cpu_total"] = procTimeTotal / REP_INTERVAL / Environment.ProcessorCount * 100;
                        metrics["cpu_antitotal"] = procTimeTotalAnti / REP_INTERVAL  * 100;

                        Console.WriteLine("Processor {0}% ETW Check", concurrency.Sum());
                        Console.WriteLine("Processor {0}% ETW", procTimeTotal / REP_INTERVAL / Environment.ProcessorCount * 100);
                        Console.WriteLine("ProcessorAnti {0}% ETW", procTimeTotalAnti / REP_INTERVAL  * 100);
                        Array.Clear(concurrency, 0, concurrency.Length);

                        collector.Write(DB_NAME, metrics);

                        nextReport += REP_INTERVAL;
                    }
                };

                session.Source.Process();
            }
        }

        #endregion Methods
    }
}