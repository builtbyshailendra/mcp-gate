package gate

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are the gate's Prometheus series. Labels only take values from the
// config and the schema (agents, tools, reasons), never from request bodies,
// so a caller can't blow up the number of series.
type Metrics struct {
	Registry       *prometheus.Registry
	Requests       *prometheus.CounterVec
	Decisions      *prometheus.CounterVec
	DecisionTime   prometheus.Histogram
	Rejected       *prometheus.CounterVec
	ToolsHidden    *prometheus.CounterVec
	UpstreamErrors prometheus.Counter
	Reloads        *prometheus.CounterVec
	PoliciesLoaded prometheus.Gauge
}

// NewMetrics registers every series on a fresh registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgate_requests_total", Help: "Requests by JSON-RPC method (or HTTP verb for GET/DELETE).",
		}, []string{"method"}),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgate_decisions_total", Help: "tools/call decisions.",
		}, []string{"agent", "tool", "decision"}),
		DecisionTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "mcpgate_decision_seconds", Help: "Time to decide one tools/call.",
			Buckets: []float64{.00001, .000025, .00005, .0001, .00025, .0005, .001, .005},
		}),
		Rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgate_rejected_total", Help: "Requests refused before any policy ran.",
		}, []string{"reason"}),
		ToolsHidden: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgate_tools_hidden_total", Help: "Tools removed from tools/list replies.",
		}, []string{"agent"}),
		UpstreamErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcpgate_upstream_errors_total", Help: "Requests that failed to reach the upstream MCP server.",
		}),
		Reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcpgate_policy_reloads_total", Help: "Policy reload attempts.",
		}, []string{"result"}),
		PoliciesLoaded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mcpgate_policies_loaded", Help: "Policies in the active set.",
		}),
	}
	m.Registry.MustRegister(m.Requests, m.Decisions, m.DecisionTime, m.Rejected, m.ToolsHidden,
		m.UpstreamErrors, m.Reloads, m.PoliciesLoaded)
	return m
}

// Handler serves /metrics for this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
