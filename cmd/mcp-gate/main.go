// Command mcp-gate runs the gate, tests policies, and hashes agent tokens.
//
//	mcp-gate serve -config gate.yaml
//	mcp-gate test  -config gate.yaml [-cases policies/tests.yaml]
//	mcp-gate check -config gate.yaml
//	mcp-gate hash-token <token>
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
	_ "time/tzdata" // time zones without relying on the OS database (Windows has none)

	"github.com/builtbyshailendra/mcp-gate/internal/audit"
	"github.com/builtbyshailendra/mcp-gate/internal/authz"
	"github.com/builtbyshailendra/mcp-gate/internal/config"
	"github.com/builtbyshailendra/mcp-gate/internal/gate"
	"github.com/builtbyshailendra/mcp-gate/internal/policytest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "test":
		err = test(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "hash-token":
		if len(os.Args) != 3 {
			usage()
		}
		sum := sha256.Sum256([]byte(os.Args[2]))
		fmt.Println(hex.EncodeToString(sum[:]))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-gate:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  mcp-gate serve -config gate.yaml          run the gate
  mcp-gate test  -config gate.yaml          run the policy test cases
  mcp-gate check -config gate.yaml          load the policies and show who sees which tools
  mcp-gate hash-token <token>               print the sha256 to put in the config`)
	os.Exit(2)
}

func loadConfig(name string, args []string) (*config.Config, *flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("config", "gate.yaml", "config file")
	cases := fs.String("cases", "", "policy test cases (default: tests.yaml in the policy dir)")
	_ = fs.Parse(args)
	c, err := config.Load(*path)
	if err == nil && *cases == "" {
		*cases = filepath.Join(c.Policies.Dir, "tests.yaml")
	}
	return c, fs, err
}

func serve(args []string) error {
	c, _, err := loadConfig("serve", args)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var auditOut io.Writer = os.Stdout
	if c.AuditLog != "" && c.AuditLog != "-" {
		f, err := os.OpenFile(c.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		auditOut = f
	}
	auditLog := audit.New(auditOut)
	metrics := gate.NewMetrics()

	store, err := authz.NewStore(c.Policies.Dir, c.AuthzAgents(), c.Upstream.Name)
	if err != nil {
		return fmt.Errorf("policies: %w", err)
	}
	metrics.PoliciesLoaded.Set(float64(len(store.Engine().PolicyIDs())))
	store.OnReload = func(e *authz.Engine, err error) {
		if err != nil {
			metrics.Reloads.WithLabelValues("failed").Inc()
			auditLog.Write(audit.Event{Kind: "reload", Decision: "kept-previous", Reason: err.Error()})
			logger.Error("policy reload failed; still enforcing the previous set", "error", err)
			return
		}
		metrics.Reloads.WithLabelValues("ok").Inc()
		metrics.PoliciesLoaded.Set(float64(len(e.PolicyIDs())))
		auditLog.Write(audit.Event{Kind: "reload", Decision: "applied", Policies: e.PolicyIDs()})
		logger.Info("policies reloaded", "policies", len(e.PolicyIDs()))
	}

	upstreamToken := ""
	if c.Upstream.TokenEnv != "" {
		upstreamToken = os.Getenv(c.Upstream.TokenEnv)
	}
	g, err := gate.New(gate.Options{
		Upstream: c.UpstreamURL, UpstreamToken: upstreamToken, Engine: store.Engine, Tokens: c.Tokens(),
		Audit: auditLog, Metrics: metrics, Logger: logger, Location: c.Location,
		MaxBodyBytes: c.MaxBodyBytes, ExtraMethods: c.ExtraMethods,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go store.Watch(ctx, c.Policies.ReloadEvery)

	mux := http.NewServeMux()
	mux.Handle("/mcp", g)
	main := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	// No WriteTimeout: MCP streams legitimately stay open for a long time.

	admin := http.NewServeMux()
	admin.Handle("/metrics", metrics.Handler())
	admin.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	adminSrv := &http.Server{Addr: c.AdminListen, Handler: admin, ReadHeaderTimeout: 10 * time.Second}

	errs := make(chan error, 2)
	go func() { errs <- main.ListenAndServe() }()
	go func() { errs <- adminSrv.ListenAndServe() }()
	logger.Info("mcp-gate listening", "agents", "http://"+c.Listen+"/mcp", "upstream", c.UpstreamURL.String(),
		"admin", "http://"+c.AdminListen, "policies", len(store.Engine().PolicyIDs()), "tools", strings.Join(store.Engine().Tools(), ","))

	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shutdown)
	return main.Shutdown(shutdown)
}

func test(args []string) error {
	c, fs, err := loadConfig("test", args)
	if err != nil {
		return err
	}
	e, err := authz.LoadDir(c.Policies.Dir, c.AuthzAgents(), c.Upstream.Name)
	if err != nil {
		return fmt.Errorf("policies: %w", err)
	}
	cases, err := policytest.Load(fs.Lookup("cases").Value.String())
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range policytest.Run(e, cases, c.Location) {
		if r.Pass() {
			fmt.Printf("PASS  %s\n", r.Case.Name)
			continue
		}
		failed++
		fmt.Printf("FAIL  %s\n      %s\n", r.Case.Name, strings.Join(r.Problems, "\n      "))
	}
	fmt.Printf("\n%d of %d policy cases passed\n", len(cases)-failed, len(cases))
	if failed > 0 {
		return fmt.Errorf("%d policy case(s) failed", failed)
	}
	return nil
}

func check(args []string) error {
	c, _, err := loadConfig("check", args)
	if err != nil {
		return err
	}
	e, err := authz.LoadDir(c.Policies.Dir, c.AuthzAgents(), c.Upstream.Name)
	if err != nil {
		return fmt.Errorf("policies: %w", err)
	}
	fmt.Printf("%d policies load and type-check: %s\n\n", len(e.PolicyIDs()), strings.Join(e.PolicyIDs(), ", "))
	fmt.Println("Which tools each agent can see (and might be allowed to call):")
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprint(tw, "agent")
	for _, tool := range e.Tools() {
		fmt.Fprint(tw, "\t"+tool)
	}
	fmt.Fprintln(tw)
	for _, a := range c.AuthzAgents() {
		fmt.Fprint(tw, a.ID)
		for _, tool := range e.Tools() {
			mark := "-"
			if e.Visible(a.ID, tool) {
				mark = "yes"
			}
			fmt.Fprint(tw, "\t"+mark)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}
