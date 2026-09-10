package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/container-registry/harbor-scanner-trivy/pkg/ext"
	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

type Format string

const (
	trivyCmd = "trivy"

	FormatJSON      Format = "json"
	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx"
)

type ImageRef struct {
	Name   string
	Auth   RegistryAuth
	NonSSL bool
}

type ScanOption struct {
	Format Format
}

// RegistryAuth wraps registry credentials.
type RegistryAuth interface{}

type NoAuth struct{}

type BasicAuth struct {
	Username string
	Password string
}

type BearerAuth struct {
	Token string
}

type Wrapper interface {
	Scan(ctx context.Context, imageRef ImageRef, opt ScanOption) (Report, error)
	GetVersion() (VersionInfo, error)
}

type wrapper struct {
	metrics    *metrics.Recorder
	config     etc.Trivy
	ambassador ext.Ambassador
}

func NewWrapper(config etc.Trivy, ambassador ext.Ambassador, recorders ...*metrics.Recorder) Wrapper {
	backend := config.CacheBackend
	if strings.HasPrefix(backend, "redis") {
		backend = "redis"
	}
	slog.Info("Trivy scan cache configured", "backend", backend, "ttl", config.CacheTTL)
	return &wrapper{
		metrics:    metrics.Optional(recorders),
		config:     config,
		ambassador: ambassador,
	}
}

func (w *wrapper) Scan(ctx context.Context, imageRef ImageRef, opt ScanOption) (Report, error) {
	if w.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, w.config.Timeout)
		defer cancel()
	}
	report, usedAccessory, err := w.scan(ctx, imageRef, opt, w.useSBOMAccessory(opt))
	if err == nil && usedAccessory {
		w.metrics.Inc("sbom_accessory_events_total", "reuse_success")
	}
	if err != nil && usedAccessory && ctx.Err() == nil {
		w.metrics.Inc("sbom_accessory_events_total", "fallback")
		slog.Warn("SBOM accessory scan failed, retrying as image scan",
			slog.String("image_ref", imageRef.Name),
			slog.String("err", err.Error()))
		report, _, err = w.scan(ctx, imageRef, opt, false)
	}
	return report, err
}

// useSBOMAccessory reports whether the scan may be served from a pre-existing
// SBOM accessory. Only vulnerability scans qualify: SBOM generation must read
// the image, and secret/misconfig scanners need image content an SBOM lacks.
func (w *wrapper) useSBOMAccessory(opt ScanOption) bool {
	if !w.config.UseSBOMAccessory || opt.Format != FormatJSON {
		return false
	}
	for _, s := range strings.Split(w.config.Scanners, ",") {
		if strings.TrimSpace(s) != "vuln" {
			return false
		}
	}
	return true
}

func (w *wrapper) scan(ctx context.Context, imageRef ImageRef, opt ScanOption, useSBOMAccessory bool) (Report, bool, error) {
	logger := slog.With(slog.String("image_ref", imageRef.Name))
	logger.Debug("Started scanning")

	target, err := newTarget(ctx, imageRef, w.config, w.ambassador, useSBOMAccessory, w.metrics)
	if err != nil {
		return Report{}, false, xerrors.Errorf("creating scan target: %w", err)
	}
	defer func() {
		if err = target.Clean(); err != nil {
			logger.Warn("Error while removing sbom tmp file", slog.String("err", err.Error()))
		}
	}()

	reportFile, err := w.ambassador.TempFile(w.config.ReportsDir, "scan_report_*.json")
	if err != nil {
		return Report{}, target.fromAccessory, xerrors.Errorf("creating scan report tmp file: %w", err)
	}
	logger.Debug("Saving scan report to tmp file", slog.String("path", reportFile.Name()))
	defer func() {
		if err = reportFile.Close(); err != nil {
			logger.Warn("Error while closing scan report tmp file", slog.String("err", err.Error()))
		}
		logger.Debug("Removing scan report tmp file", slog.String("path", reportFile.Name()))
		if err = os.Remove(reportFile.Name()); err != nil {
			logger.Warn("Error while removing scan report tmp file", slog.String("err", err.Error()))
		}
	}()

	cmd, err := w.prepareScanCmd(ctx, target, reportFile.Name(), opt)
	if err != nil {
		return Report{}, target.fromAccessory, xerrors.Errorf("preparing scan command: %w", err)
	}

	logger.Debug("Exec command with args", slog.String("path", cmd.Path),
		slog.String("args", strings.Join(cmd.Args, " ")))

	stdout, err := w.metrics.Run(string(target.kind), cmd, w.ambassador.RunCmd)
	if err != nil {
		// Classify before redaction: a short password may also occur in an error keyword.
		category := classifyTrivyError(string(stdout))
		output := w.redactCacheCredentials(string(stdout))
		targetName, _ := target.Name()
		logger.Error("Running trivy failed",
			slog.String("exit_code", fmt.Sprintf("%d", exitCode(cmd))),
			slog.String("std_out", output),
			slog.String("category", string(category)),
		)
		return Report{}, target.fromAccessory, &ScanError{
			Category:  category,
			Retryable: category != ErrCategoryAuth && category != ErrCategoryUnscannable,
			ImageRef:  targetName,
			Detail:    output,
			Cause:     &redactedError{cause: err, message: w.redactCacheCredentials(err.Error())},
		}
	}

	logger.Debug("Running trivy finished",
		slog.String("exit_code", fmt.Sprintf("%d", exitCode(cmd))),
		slog.String("std_out", w.redactCacheCredentials(string(stdout))),
	)

	report, err := w.parseReport(opt.Format, reportFile)
	if err != nil {
		return Report{}, target.fromAccessory, &ScanError{
			Category: ErrCategoryReportParse,
			ImageRef: imageRef.Name,
			Detail:   err.Error(),
			Cause:    err,
		}
	}
	return report, target.fromAccessory, nil
}

func (w *wrapper) parseReport(format Format, reportFile io.Reader) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReport(reportFile)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOM(reportFile)
	}
	return Report{}, xerrors.Errorf("unsupported format %s", format)
}

func (w *wrapper) parseJSONReport(reportFile io.Reader) (Report, error) {
	var scanReport ScanReport
	if err := json.NewDecoder(reportFile).Decode(&scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}

	if scanReport.SchemaVersion != SchemaVersion {
		return Report{}, xerrors.Errorf("unsupported schema %d, expected %d", scanReport.SchemaVersion, SchemaVersion)
	}

	var vulnerabilities []Vulnerability
	for _, scanResult := range scanReport.Results {
		slog.Debug("Parsing vulnerabilities", slog.String("target", scanResult.Target))
		vulnerabilities = append(vulnerabilities, scanResult.Vulnerabilities...)
	}

	return Report{
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (w *wrapper) parseSBOM(reportFile io.Reader) (Report, error) {
	var doc any
	if err := json.NewDecoder(reportFile).Decode(&doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) prepareScanCmd(ctx context.Context, target ScanTarget, outputFile string, opt ScanOption) (*exec.Cmd, error) {
	args := []string{
		string(target.kind), // subcommand
		"--no-progress",
		"--severity",
		w.config.Severity,
		"--vuln-type",
		w.config.VulnType,
		"--format",
		string(opt.Format),
		"--output",
		outputFile,
		"--cache-dir",
		w.config.CacheDir,
		"--timeout",
		w.config.Timeout.String(),
	}

	if target.kind == TargetImage {
		args = append(args, "--scanners", w.config.Scanners)
	}

	if w.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	if w.config.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	if w.config.SkipJavaDBUpdate {
		args = append(args, "--skip-java-db-update")
	}

	if w.config.OfflineScan {
		args = append(args, "--offline-scan")
	}

	if w.config.IgnorePolicy != "" {
		args = append(args, "--ignore-policy", w.config.IgnorePolicy)
	}

	if w.config.DBRepository != "" {
		args = append(args, "--db-repository", w.config.DBRepository)
	}

	if w.config.JavaDBRepository != "" {
		args = append(args, "--java-db-repository", w.config.JavaDBRepository)
	}

	if w.config.DebugMode {
		args = append(args, "--debug")
	}

	if w.config.Insecure || target.NonSSL() {
		args = append(args, "--insecure")
	}

	if w.config.VEXSource != "" {
		args = append(args, "--vex", w.config.VEXSource)
	}

	if w.config.SkipVEXRepoUpdate {
		args = append(args, "--skip-vex-repo-update")
	}

	targetName, err := target.Name()
	if err != nil {
		return nil, xerrors.Errorf("get target name: %w", err)
	}
	args = append(args, targetName)

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second

	cmd.Env = w.cacheEnv(w.ambassador.Environ())

	switch a := target.Auth().(type) {
	case NoAuth:
	case BasicAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_USERNAME=%s", a.Username),
			fmt.Sprintf("TRIVY_PASSWORD=%s", a.Password))
	case BearerAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("TRIVY_REGISTRY_TOKEN=%s", a.Token))
	default:
		return nil, fmt.Errorf("invalid auth type %T", a)
	}

	if strings.TrimSpace(w.config.GitHubToken) != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GITHUB_TOKEN=%s", w.config.GitHubToken))
	}

	return cmd, nil
}

// Keep errors.Is/As useful without exposing credentials in formatted errors.
type redactedError struct {
	cause   error
	message string
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

func (w *wrapper) redactCacheCredentials(text string) string {
	u, err := url.Parse(w.config.CacheBackend)
	if err != nil || u.User == nil {
		return text
	}
	text = strings.ReplaceAll(text, w.config.CacheBackend, "redis://[redacted]")
	if u.Scheme == "rediss" {
		text = strings.ReplaceAll(text, "redis://"+strings.TrimPrefix(w.config.CacheBackend, "rediss://"), "redis://[redacted]")
	}
	text = strings.ReplaceAll(text, u.User.String(), "[redacted]")
	if password, ok := u.User.Password(); ok && password != "" {
		// URL userinfo encoding differs from QueryEscape (notably spaces).
		encoded := strings.TrimPrefix(url.UserPassword("", password).String(), ":")
		text = strings.ReplaceAll(text, encoded, "[redacted]")
		text = strings.ReplaceAll(text, url.QueryEscape(password), "[redacted]")
		text = strings.ReplaceAll(text, password, "[redacted]")
	}
	return text
}

// Pass cache credentials through the child environment, never command arguments.
// Explicit adapter settings take precedence over inherited native Trivy settings.
func (w *wrapper) cacheEnv(env []string) []string {
	if w.config.CacheBackend == "" {
		return env
	}
	backend, enableTLS := w.config.CacheBackend, w.config.CacheRedisTLS
	// Trivy selects the Redis backend only for redis://; preserve rediss://
	// semantics by enabling its separate TLS option before normalizing the URL.
	if strings.HasPrefix(backend, "rediss://") {
		backend = "redis://" + strings.TrimPrefix(backend, "rediss://")
		enableTLS = true
	}
	values := []string{
		"TRIVY_CACHE_BACKEND=" + backend,
		"TRIVY_CACHE_TTL=" + w.config.CacheTTL.String(),
		fmt.Sprintf("TRIVY_REDIS_TLS=%t", enableTLS),
		"TRIVY_REDIS_CA=" + w.config.CacheRedisCA,
		"TRIVY_REDIS_CERT=" + w.config.CacheRedisCert,
		"TRIVY_REDIS_KEY=" + w.config.CacheRedisKey,
	}
	for _, value := range values {
		key, _, _ := strings.Cut(value, "=")
		filtered := make([]string, 0, len(env)+1)
		for _, entry := range env {
			if !strings.HasPrefix(entry, key+"=") {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, value)
	}
	return env
}

// classifyTrivyError categorizes Trivy CLI errors by pattern-matching the output.
func classifyTrivyError(output string) ScanErrorCategory {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "redis cache") || strings.Contains(lower, "layer cache missing") || strings.Contains(lower, "cache may be in use") {
		return ErrCategoryCache
	}
	switch {
	case strings.Contains(lower, "unauthorized") || strings.Contains(lower, "401") || strings.Contains(lower, "403 forbidden"):
		return ErrCategoryAuth
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host") || strings.Contains(lower, "dial tcp"):
		return ErrCategoryNetwork
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return ErrCategoryTimeout
	case strings.Contains(lower, "failed to extract the archive") || strings.Contains(lower, "unexpected eof"):
		return ErrCategoryUnscannable
	default:
		return ErrCategoryTrivyExec
	}
}

func (w *wrapper) GetVersion() (VersionInfo, error) {
	cmd, err := w.prepareVersionCmd()
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed preparing trivy version command: %w", err)
	}

	versionOutput, err := w.metrics.Run("version", cmd, w.ambassador.RunCmd)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed running trivy version command: %w: %v", err, string(versionOutput))
	}

	var vi VersionInfo
	err = json.Unmarshal(versionOutput, &vi)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed parsing trivy version output: %w", err)
	}

	return vi, nil
}

func (w *wrapper) prepareVersionCmd() (*exec.Cmd, error) {
	args := []string{
		"--cache-dir",
		w.config.CacheDir,
		"version",
		"--format",
		"json",
	}

	name, err := w.ambassador.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	return cmd, nil
}

func exitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}
