antimetrics
===========

Antimetrics is an application for collection of a process health metrics (like CPU and memory consumptions) via API and ETW counters and publishing them into an database for further analyses.


Quickstart Guide
================

Antimetrics is only aimed at data collection and does not contain a functionality for storaging and visualizing collected data.
The most widespread storage backend is InfluxDB (it is a joke, as it is the only one supported storage backend now).
It is an awesome open-source time-series database written on Go which works on all popular operating systems.
It is published in all popular repositories including [Chocolatey](https://chocolatey.org/packages/influxdb), but for a quick start it is OK to use the binaries from [official site](https://portal.influxdata.com/downloads/) in a "portable way" (with the database placed in the same directory) which can be done with the following changes in `influxdb.conf`:

    [meta]
      dir = "./db/meta"
    [data]
      dir = "./db/data"
      wal-dir = "./db/wal"

And run with the following command (can be saved as the script `influxd.cmd`):

    influxd.exe run -config influxdb.conf

After you have run the InfluxDB daemon, it is also necessary to create the database for antimetrics, run `influx.exe` and execute the following command:

    create database antimetrics

For deployments more ready for production, please, read the official [InfluxDB documentation](https://docs.influxdata.com/influxdb/).
Especially, I recommend to read a part about its [internals](https://docs.influxdata.com/influxdb/v1.7/concepts/).

There can be used a different front-end for metrics visualization, for example, [Chronograph](https://portal.influxdata.com/downloads/) from the same developers or a more functional software such as [Graphana](https://grafana.com/).
`Chronograph` also can be run in a "portable way" manner.
So, download it and run (`chronograf.cmd`):

    chronograf.exe /port:9000

All preparations have been done, now is time to run antimetrics:

    antimetrics.exe -h http://127.0.0.1:8086 Calculator
    Process Calculator is not found, waiting...
    Process Calculator started, new pid 12345

Antimetrics CLI takes a list of names of processes (one is a minimum, and a maximum is limited by your hardware and sanity), and a few optional arguments, such as `-h <influxdb address>`.
For full CLI arguments information run it with the flag `--help` and believe that the output is much more than the document you are reading right now!

Antimetrics starts to monitor and sends the metrics values to the InfluxDB.
It is not necessary to create a database scheme for the InfluxDB because it can be generated/modified automatically when some data will be written into it.
The next step is to open the Chronograph and visualize collected data, open in a browser [your chronograph page](http://127.0.0.1:9000) and do the following steps:

- Click "Explore" on the left panel.
- Select `antimetrics.autogen` database in the left column.
- Add filter it by your `application` and `host` in the middle column.
- Choose metrics useful for you in the right column.
- Click on `Submit` above.
- If everything is fine, send resulted graph to dashboard by clicking `Send to Dashboard` in the top right corner.

For more advanced usage scenarios, please, read the official [Chronograph documentation](https://docs.influxdata.com/chronograf/).


Background
==========

This app was inspired by the following great presentations:

- Pavel Yosifovich - [Building your own profiling and diagnosis tools with Event Tracing for Windows](https://www.youtube.com/watch?v=gBkvAO02qUY).
- Anatoly Kulakov - [The Metrix has you...](https://www.youtube.com/watch?v=AFB89L8DLpE).

It also contains a result of some interesting observations which was described in the post ["Calculation of CPU Utilization" or "What Can be Simpler"?](https://anticode.ninja/posts/20200221_cpu_time/).
