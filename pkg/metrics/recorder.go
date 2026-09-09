// Package metrics records adapter operations. A nil Recorder disables collection.
package metrics

import (
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/container-registry/harbor-scanner-trivy/pkg/http/api"
	"github.com/container-registry/harbor-scanner-trivy/pkg/job"
)

const Prefix = "harbor_scanner_trivy_"

// Labels are normalized at the recorder boundary, including values originating
// in malformed HTTP requests or queue messages. Versions come from the binaries.
var values = map[string][]string{
	"capability": {"vulnerability", "sbom", "other"},
	"format":     {"json", "spdx-json", "cyclonedx", "other"},
	"outcome":    {"success", "failed", "error", "not_found", "not_applied", "other"},
	"command":    {"image", "sbom", "version", "other"},
	"stage":      {"status", "target", "auth", "scan", "transform", "report", "internal", "other"},
	"category":   {"image_fetch", "manifest", "auth", "unscannable_layer", "trivy_execution", "network", "timeout", "report_parse", "storage_full", "storage_io", "persistence", "cache", "internal", "unknown", "other"},
	"encoding":   {"raw", "compressed", "other"},
	"record":     {"job", "report", "other"},
	"operation":  {"create", "status", "read", "report", "acknowledge", "other"},
	"database":   {"vulnerability", "java", "other"},
	"kind":       {"analysis", "vulnerability_db", "java_db", "other"},
	"area":       {"cache", "reports", "other"},
	"collector":  {"cache_size", "cache_filesystem", "reports_filesystem", "other"},
	"event":      {"lookup_hit", "lookup_miss", "lookup_error", "reuse_success", "fallback", "other"},
	"reason":     {"success", "nonzero_exit", "signal", "start_error", "other"},
	"result":     {"lock_acquired", "lock_busy", "lock_error", "decode_error", "ok", "pending", "failed", "not_found", "error", "invalid_request", "not_applied", "success", "other"},
	"method":     {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "other"},
	"route":      {"/api/v1/scan", "/api/v1/scan/{scan_request_id}/report", "/api/v1/metadata", "unmatched", "other"},
}

type definition struct {
	name, help, kind string
	labels           []string
	buckets          []float64
}

// Histograms cover the default five-minute timeout and up to the supported 24h.
var (
	executionBuckets = []float64{0.1, 1, 5, 10, 30, 60, 120, 300, 600, 1200, 3600, 14400, 86400}
	byteBuckets      = prometheus.ExponentialBuckets(1024, 4, 10)
)

var catalog = []definition{
	{"scan_retries_total", "Attempts after interrupted execution or cache failure.", "counter", nil, nil},
	{"lease_losses_total", "Failed lease renewals or lost ownership.", "counter", nil, nil},
	{"queue_unacknowledged_jobs", "Shared unacknowledged stream length; use max across pods, not sum.", "gauge", nil, nil},
	{"queue_oldest_age_seconds", "Age of oldest unacknowledged delivery; sampled between scans.", "gauge", nil, nil},
	{"build_info", "Adapter and Trivy binary versions.", "gauge", []string{"adapter_version", "trivy_version"}, nil},
	{"http_requests_total", "API requests by route template.", "counter", []string{"route", "method", "code"}, nil},
	{"http_request_duration_seconds", "API handler duration.", "histogram", []string{"route", "method"}, prometheus.DefBuckets},
	{"jobs_enqueued_total", "Durably enqueued tasks.", "counter", []string{"capability", "format"}, nil},
	{"job_dispatch_total", "Worker dispatch outcomes, including skipped locks.", "counter", []string{"result"}, nil},
	{"publish_no_subscribers_total", "Deprecated Pub/Sub metric; Streams do not require an online subscriber.", "counter", nil, nil},
	{"job_attempts_total", "Observed execution attempts, including retryable failures; not unique artifacts or terminal jobs.", "counter", []string{"capability", "format", "outcome"}, nil},
	{"job_failures_total", "Primary failures of controller executions.", "counter", []string{"stage", "category"}, nil},
	{"job_duration_seconds", "Controller processing and persistence duration after lock acquisition.", "histogram", []string{"capability", "outcome"}, executionBuckets},
	{"queue_wait_duration_seconds", "Adapter enqueue-to-lock-acquisition duration, excluding Harbor's queue.", "histogram", []string{"capability"}, executionBuckets},
	{"jobs_in_progress", "Locally executing jobs.", "gauge", nil, nil},
	{"worker_concurrency", "Configured local worker capacity.", "gauge", nil, nil},
	{"last_scan_success_timestamp_seconds", "Last successfully persisted completion; absent until observed.", "gauge", nil, nil},
	{"scan_timeout_seconds", "Configured Trivy CLI timeout, not the entire job budget.", "gauge", nil, nil},
	{"subprocess_duration_seconds", "Trivy child process duration.", "histogram", []string{"command", "outcome"}, executionBuckets},
	{"subprocess_exits_total", "Trivy child termination reason; signal does not imply OOM.", "counter", []string{"command", "reason"}, nil},
	{"subprocess_max_rss_bytes", "Completed child peak RSS, not container peak or live usage.", "histogram", []string{"command"}, prometheus.ExponentialBuckets(1<<20, 2, 15)},
	{"sbom_accessory_events_total", "SBOM accessory lookup and fallback events (multiple per job).", "counter", []string{"event"}, nil},
	{"report_size_bytes", "Matched raw and compressed report sizes on applied writes.", "histogram", []string{"capability", "format", "encoding"}, byteBuckets},
	{"store_bytes_written_total", "Applied payload bytes; raw is uncompressed equivalent, not resident memory.", "counter", []string{"record", "encoding"}, nil},
	{"store_operations_total", "Logical adapter store operations and outcomes.", "counter", []string{"operation", "outcome"}, nil},
	{"store_operation_duration_seconds", "Logical adapter store operation duration including failures.", "histogram", []string{"operation"}, prometheus.DefBuckets},
	{"report_fetch_total", "Report poll outcomes; not_found does not prove expiry.", "counter", []string{"result"}, nil},
	{"report_fetch_age_seconds", "Age of successfully fetched report since recorded completion, not remaining TTL.", "histogram", []string{"capability", "format"}, executionBuckets},
	{"scan_job_ttl_seconds", "Effective retention TTL; zero disables expiry in the store.", "gauge", nil, nil},
	{"db_present", "Local database file and metadata presence (not read integrity).", "gauge", []string{"database"}, nil},
	{"db_updated_timestamp_seconds", "Database content build timestamp.", "gauge", []string{"database"}, nil},
	{"db_next_update_timestamp_seconds", "Advertised database next update timestamp.", "gauge", []string{"database"}, nil},
	{"db_downloaded_timestamp_seconds", "Recorded local download timestamp, not download attempts.", "gauge", []string{"database"}, nil},
	{"db_updates_enabled", "Effective automatic database update policy.", "gauge", []string{"database"}, nil},
	{"metadata_collection_success", "Whether the last metadata refresh succeeded.", "gauge", nil, nil},
	{"metadata_last_success_timestamp_seconds", "Last successful metadata refresh.", "gauge", nil, nil},
	{"cache_size_bytes", "Logical regular-file bytes for the verified local cache layout.", "gauge", []string{"kind"}, nil},
	{"storage_capacity_bytes", "Filesystem capacity at the configured path; areas may share a filesystem.", "gauge", []string{"area"}, nil},
	{"storage_available_bytes", "Filesystem bytes available to the scanner at the configured path.", "gauge", []string{"area"}, nil},
	{"storage_inodes_available", "Available filesystem inodes where supported.", "gauge", []string{"area"}, nil},
	{"storage_collection_success", "Whether the latest storage collector run succeeded.", "gauge", []string{"collector"}, nil},
	{"storage_collection_duration_seconds", "Background storage collection duration.", "histogram", []string{"collector"}, prometheus.DefBuckets},
	{"storage_last_success_timestamp_seconds", "Last successful storage collection.", "gauge", []string{"collector"}, nil},
}

type Recorder struct {
	registry    *prometheus.Registry
	counters    map[string]*prometheus.CounterVec
	gauges      map[string]*prometheus.GaugeVec
	histograms  map[string]*prometheus.HistogramVec
	definitions map[string]definition
	mu          sync.Mutex
	running     map[*time.Time]struct{}
}

func New(enabled bool) *Recorder {
	if !enabled {
		return nil
	}
	r := &Recorder{registry: prometheus.NewRegistry(), counters: map[string]*prometheus.CounterVec{}, gauges: map[string]*prometheus.GaugeVec{}, histograms: map[string]*prometheus.HistogramVec{}, definitions: map[string]definition{}, running: map[*time.Time]struct{}{}}
	r.registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	for _, d := range catalog {
		r.definitions[d.name] = d
		switch d.kind {
		case "counter":
			v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: Prefix + d.name, Help: d.help}, d.labels)
			r.counters[d.name] = v
			r.registry.MustRegister(v)
			if len(d.labels) == 0 {
				v.WithLabelValues()
			}
		case "gauge":
			v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: Prefix + d.name, Help: d.help}, d.labels)
			r.gauges[d.name] = v
			r.registry.MustRegister(v)
		case "histogram":
			v := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: Prefix + d.name, Help: d.help, Buckets: d.buckets}, d.labels)
			r.histograms[d.name] = v
			r.registry.MustRegister(v)
		}
	}
	r.Set("jobs_in_progress", 0)
	r.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: Prefix + "oldest_running_job_age_seconds", Help: "Oldest local execution age; zero while idle."}, r.oldest))
	for _, capability := range []string{"vulnerability", "sbom"} {
		for _, format := range []string{"json", "spdx-json", "cyclonedx"} {
			r.Add("jobs_enqueued_total", 0, capability, format)
			for _, outcome := range []string{"success", "failed"} {
				r.Add("job_attempts_total", 0, capability, format, outcome)
			}
		}
	}
	for _, result := range []string{"ok", "pending", "failed", "not_found", "error", "invalid_request"} {
		r.Add("report_fetch_total", 0, result)
	}
	for _, result := range []string{"lock_acquired", "lock_busy", "lock_error", "decode_error"} {
		r.Add("job_dispatch_total", 0, result)
	}
	for _, event := range values["event"] {
		if event != "other" {
			r.Add("sbom_accessory_events_total", 0, event)
		}
	}
	for _, record := range []string{"job", "report"} {
		for _, encoding := range []string{"raw", "compressed"} {
			r.Add("store_bytes_written_total", 0, record, encoding)
		}
	}
	for _, op := range []string{"create", "read", "report", "status"} {
		for _, outcome := range []string{"success", "error", "not_found", "not_applied"} {
			r.Add("store_operations_total", 0, op, outcome)
		}
	}
	return r
}

// Optional preserves constructor compatibility for users that do not collect metrics.
func Optional(rs []*Recorder) *Recorder {
	if len(rs) == 0 {
		return nil
	}
	return rs[0]
}

func (r *Recorder) Handler() http.Handler {
	if r == nil {
		return promhttp.Handler()
	}
	return promhttp.InstrumentMetricHandler(r.registry, promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{}))
}

func (r *Recorder) Gatherer() prometheus.Gatherer {
	if r == nil {
		return prometheus.Gatherers{}
	}
	return r.registry
}

func (r *Recorder) normalize(name string, labels []string) []string {
	d := r.definitions[name]
	if len(labels) != len(d.labels) {
		panic("invalid metric labels: " + name)
	}
	out := slices.Clone(labels)
	for i, label := range d.labels {
		if allowed, ok := values[label]; ok && !slices.Contains(allowed, out[i]) {
			out[i] = "other"
		}
		if label == "code" && !validCode(out[i]) {
			out[i] = "other"
		}
	}
	return out
}

func validCode(s string) bool {
	return len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}
func (r *Recorder) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }
func (r *Recorder) Add(name string, n float64, labels ...string) {
	if r != nil {
		r.counters[name].WithLabelValues(r.normalize(name, labels)...).Add(n)
	}
}

func (r *Recorder) Set(name string, n float64, labels ...string) {
	if r != nil {
		r.gauges[name].WithLabelValues(r.normalize(name, labels)...).Set(n)
	}
}

func (r *Recorder) Delete(name string, labels ...string) {
	if r != nil {
		r.gauges[name].DeleteLabelValues(r.normalize(name, labels)...)
	}
}

func (r *Recorder) Observe(name string, n float64, labels ...string) {
	if r != nil {
		r.histograms[name].WithLabelValues(r.normalize(name, labels)...).Observe(n)
	}
}

func (r *Recorder) oldest() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var age float64
	for started := range r.running {
		age = max(age, time.Since(*started).Seconds())
	}
	return age
}

// BeginExecution is called after lock acquisition. Completion records the actual
// processing outcome, independently of whether writing Failed returned nil.
func (r *Recorder) BeginExecution(key job.ScanJobKey) func(bool, string, string) {
	if r == nil {
		return func(bool, string, string) {}
	}
	started := time.Now()
	r.mu.Lock()
	r.running[&started] = struct{}{}
	r.Set("jobs_in_progress", float64(len(r.running)))
	r.mu.Unlock()
	capability, format := JobLabels(key)
	return func(success bool, stage, category string) {
		r.mu.Lock()
		delete(r.running, &started)
		r.Set("jobs_in_progress", float64(len(r.running)))
		r.mu.Unlock()
		outcome := "failed"
		if success {
			outcome = "success"
			r.Set("last_scan_success_timestamp_seconds", float64(time.Now().Unix()))
		} else {
			r.Inc("job_failures_total", stage, category)
		}
		r.Inc("job_attempts_total", capability, format, outcome)
		r.Observe("job_duration_seconds", time.Since(started).Seconds(), capability, outcome)
	}
}

func JobLabels(key job.ScanJobKey) (string, string) {
	if key.MIMEType.Equal(api.MimeTypeSecurityVulnerabilityReport) {
		return "vulnerability", "json"
	}
	if key.MIMEType.Equal(api.MimeTypeSecuritySBOMReport) {
		switch key.MediaType {
		case api.MediaTypeSPDX:
			return "sbom", "spdx-json"
		case api.MediaTypeCycloneDX:
			return "sbom", "cyclonedx"
		}
		return "sbom", "other"
	}
	return "other", "other"
}
