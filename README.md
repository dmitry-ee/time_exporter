## Time Exporter
[![Build Status](https://img.shields.io/github/workflow/status/dmitry-ee/time_exporter/main.svg)](https://hub.docker.com/r/dmi7ry/time-exporter)
[![image version](https://img.shields.io/docker/v/dmi7ry/time-exporter?sort=semver)](https://hub.docker.com/r/dmi7ry/time-exporter)
[![Image Pulls](https://img.shields.io/docker/pulls/dmi7ry/time-exporter.svg)](https://hub.docker.com/r/dmi7ry/time-exporter)

Prometheus exporter for covering all possible timesync and time services.

**NOTE:** This repo is partial fork of [node_exporter](https://github.com/prometheus/node_exporter) 

**NOTE:** Exporter is only tested on linux machines

## Installation and Usage

The node_exporter listens on HTTP port 9818 by default. See the `--help` output for more options.

### Docker

```bash
docker run --rm -d \
  --name time-exporter \
  -p 9818:9818 \
  dmi7ry/time-exporter
```

### Binary

```bash
export version=0.0.1
curl -L https://github.com/dmitry-ee/time_exporter/releases/download/$version/time_exporter-$version.linux-amd64.tar.gz | tar -zxf -
./time_exporter-$version.linux-amd64/time_exporter
```

## Collectors

All collectors are enabled by default

**TBD**

### chrony
Enables and disables with flag `--collector.chrony` and `--no-collector.chrony`

### ntp
Enables and disables with flag `--collector.ntp` and `--no-collector.ntp`

### time
Enables and disables with flag `--collector.time` and `--no-collector.time`

### timex
Enables and disables with flag `--collector.timex` and `--no-collector.timex`