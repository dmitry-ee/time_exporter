## Time Exporter 

Prometheus exporter for covering all possible timesync and time services.

**NOTE:** This repo is partial fork of [node_exporter](https://github.com/prometheus/node_exporter) 

**NOTE:** Exporter is only tested on linux machines

**TBD**

## Installation and Usage

The node_exporter listens on HTTP port 9818 by default. See the --help output for more options.

### Docker

**TBD**

### Binary

**TBD**

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