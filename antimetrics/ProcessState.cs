// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

namespace Antimetrics
{
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using InfluxDB.Collector;

    internal class ProcessState
    {
        public string Name;

        public int Pid;

        public Process Process;

        public MetricsCollector Collector;

        public long[] Concurrency;
        public long ConcurrencyLast;
        public int ConcurrencyCounter;
        public ConcurrentDictionary<int, ThreadState> Threads;

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
}