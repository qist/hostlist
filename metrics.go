package hostlist

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestBlockCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "hostlist",
		Name:      "blocked_requests_total",
		Help:      "Counter of DNS requests blocked by hostlist.",
	}, []string{"server", "zone"})

	DomainsLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "hostlist",
		Name:      "domains_loaded",
		Help:      "Number of domains currently loaded in the blocklist.",
	})
)
