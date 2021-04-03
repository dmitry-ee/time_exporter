ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/time_exporter /bin/time_exporter

EXPOSE      9818
USER        nobody
ENTRYPOINT  [ "/bin/time_exporter" ]