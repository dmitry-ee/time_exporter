# Helm Chart for the Time Exporter

This [Helm](https://helm.sh/) chart deploys the Time Exporter to a
Kubernetes cluster as a
[DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/).

## Chrony Monitoring Considerations

Chrony by defaults provides its command channel through a Unix socket.
There is also an additional UDP socket that listens to the loopback
interface only by default (127.0.0.1:323).

Before actually deploying the Time Exporter to monitor Chrony, check
your access options:

- When passing the Unix socket (`/var/run/chrony/chronyd.sock`),
  ensure that the `time_exporter` process has write access to it.

- The container cannot access the host’s loopback interface unless the
  Pods runs with host network access (`hostNetwork=true`). Consider
  securing the endpoint via
  [`--web.config`](https://github.com/prometheus/node_exporter#tls-endpoint).

- Another option is to bind `chronyd` to an accessible IP address and
  configure authentication. However, the latter seems to be
  unsupported by `time_exporter` currently.

## Scraping

Typically, annotating the Kubernetes Service should be sufficient to
make the [Prometheus Service
Discovery](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config)
aware of the Time Exporter and scrape the metrics.

Example:

```yaml
service:
  annotations:
    prometheus.io/scrape: "true"
```

## Deployment Configuration (Helm Values)

See the file `values.yaml` for all available configuration options.

Do not forget to enable the desired collector. The Helm chart disables
all collectors by default except for the exporter metrics.
