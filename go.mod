module github.com/povilasv/systemd_exporter

go 1.13

require (
	github.com/coreos/go-systemd v0.0.0-20181031085051-9002847aa142
	github.com/godbus/dbus v0.0.0-20181101234600-2ff6f7ffd60f
	github.com/pkg/errors v0.8.1
	github.com/povilasv/prommod v0.0.11
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/common v0.2.0
	github.com/prometheus/procfs v0.0.0-20190319124303-40f3c57fb198
	golang.org/x/sys v0.0.0-20181116152217-5ac8a444bdc5
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)
