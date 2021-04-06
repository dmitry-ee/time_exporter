## Time Exporter
[![Build Status](https://img.shields.io/github/workflow/status/dmitry-ee/time_exporter/main.svg)](https://hub.docker.com/r/dmi7ry/time-exporter)
[![image version](https://img.shields.io/docker/v/dmi7ry/time-exporter?sort=semver)](https://hub.docker.com/r/dmi7ry/time-exporter)
[![Image Pulls](https://img.shields.io/docker/pulls/dmi7ry/time-exporter.svg)](https://hub.docker.com/r/dmi7ry/time-exporter)

Prometheus exporter for covering all possible timesync and time services.

**NOTE:** This repo is partial fork of [node_exporter](https://github.com/prometheus/node_exporter) 

**NOTE:** Exporter is only tested on linux machines

- [Time Exporter](#time-exporter)
- [Sample](#sample)
- [Installation and Usage](#installation-and-usage)
    * [Docker](#docker)
    * [Binary](#binary)
- [Collectors](#collectors)
    * [chrony](#chrony)
    * [ntp](#ntp)
    * [time](#time)
    * [timex](#timex)
    
## Sample
Before the actual usage take a look at the [metrics sample](metrics.txt)

## Installation and Usage

The time_exporter listens on HTTP port `9818` by default. See the `--help` output for more options.

### Docker

```bash
docker run --rm -d \
  --name time_exporter \
  --net=host \
  -v /var/run/chrony/chronyd.sock:/var/run/chrony/chronyd.sock:ro \
  dmi7ry/time-exporter --log.level=debug --collector.chrony.address=127.0.0.1:323
```
or

```bash
docker run --rm -d \
  --name time-exporter \
  -p 9818:9818 \
  -v /var/run/chrony/chronyd.sock:/var/run/chrony/chronyd.sock:ro \
  dmi7ry/time-exporter --log.level=debug --collector.chrony.address=/var/run/chrony/chronyd.sock
```


### Binary

```bash
export version=0.0.2
curl -L https://github.com/dmitry-ee/time_exporter/releases/download/$version/time_exporter-$version.linux-amd64.tar.gz | tar -zxf -
./time_exporter-$version.linux-amd64/time_exporter
```

## Collectors

All collectors are enabled by default

That could be disabled with both flags `--collector.disable-defaults` and if you want to get rid of the default `(go_|process_|promhttp_)` set `--web.disable-exporter-metrics`

### chrony
Enables and disables with flag `--collector.chrony` and `--no-collector.chrony`

#### `collector.chrony.address`
The most important flag here: it could be socket path (`/var/run/chrony/chronyd.sock` by default) or `host:port` (chronyd is listening `127.0.0.1:323` by default).

That could be useful to get the statistics even from outside the host itself

#### `--collector.chrony.log-response-json`
Log chronyd response in debug logging, could be helpful to get the real response for debugging purposes

### ntp
Enables and disables with flag `--collector.ntp` and `--no-collector.ntp`

### time
Enables and disables with flag `--collector.time` and `--no-collector.time`

### timex
Enables and disables with flag `--collector.timex` and `--no-collector.timex`