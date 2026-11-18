// Package demo is a stand-in MCP server: five tools over a fake, in-memory
// Kubernetes cluster. It exists so the gate has something real to protect.
// Nothing here talks to a real cluster.
package demo

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type deployment struct {
	replicas int
	restarts int
}

// Cluster is the fake cluster's state. Safe for concurrent use.
type Cluster struct {
	mu         sync.Mutex
	namespaces map[string]map[string]*deployment
}

// NewCluster returns a cluster seeded with two prod namespaces, one staging and one dev.
func NewCluster() *Cluster {
	return &Cluster{namespaces: map[string]map[string]*deployment{
		"prod-payments":    {"api": {replicas: 3}, "ledger": {replicas: 2}},
		"prod-checkout":    {"web": {replicas: 4}},
		"staging-payments": {"api": {replicas: 1}, "ledger": {replicas: 1}},
		"dev-sandbox":      {"scratch": {replicas: 1}},
	}}
}

// Replicas reports a deployment's replica count, or -1 if it doesn't exist.
func (c *Cluster) Replicas(ns, name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.namespaces[ns][name]; ok {
		return d.replicas
	}
	return -1
}

// HasNamespace reports whether the namespace still exists.
func (c *Cluster) HasNamespace(ns string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.namespaces[ns]
	return ok
}

func (c *Cluster) deployment(ns, name string) (*deployment, error) {
	deps, ok := c.namespaces[ns]
	if !ok {
		return nil, fmt.Errorf("namespace %q not found", ns)
	}
	d, ok := deps[name]
	if !ok {
		return nil, fmt.Errorf("deployment %q not found in %q", name, ns)
	}
	return d, nil
}

// Tool inputs and outputs. The SDK turns these structs into JSON Schemas, and
// rejects calls whose arguments don't match before a handler runs.

type NamespaceIn struct {
	Namespace string `json:"namespace" jsonschema:"Kubernetes namespace, for example prod-payments"`
}

type LogsIn struct {
	Namespace string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Pod       string `json:"pod" jsonschema:"pod name from list_pods"`
	Tail      int    `json:"tail,omitempty" jsonschema:"number of lines from the end (default 5)"`
}

type DeploymentIn struct {
	Namespace  string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Deployment string `json:"deployment" jsonschema:"deployment name"`
}

type ScaleIn struct {
	Namespace  string `json:"namespace" jsonschema:"Kubernetes namespace"`
	Deployment string `json:"deployment" jsonschema:"deployment name"`
	Replicas   int    `json:"replicas" jsonschema:"desired replica count"`
}

type Pod struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type PodsOut struct {
	Pods []Pod `json:"pods"`
}

type LogsOut struct {
	Lines []string `json:"lines"`
}

type ChangeOut struct {
	Message string `json:"message"`
}

func (c *Cluster) listPods(_ context.Context, _ *mcp.CallToolRequest, in NamespaceIn) (*mcp.CallToolResult, PodsOut, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deps, ok := c.namespaces[in.Namespace]
	if !ok {
		return nil, PodsOut{}, fmt.Errorf("namespace %q not found", in.Namespace)
	}
	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)
	out := PodsOut{Pods: []Pod{}}
	for _, name := range names {
		for i := range deps[name].replicas {
			out.Pods = append(out.Pods, Pod{Name: fmt.Sprintf("%s-%d", name, i), Status: "Running"})
		}
	}
	return nil, out, nil
}

func (c *Cluster) getLogs(_ context.Context, _ *mcp.CallToolRequest, in LogsIn) (*mcp.CallToolResult, LogsOut, error) {
	if !c.HasNamespace(in.Namespace) {
		return nil, LogsOut{}, fmt.Errorf("namespace %q not found", in.Namespace)
	}
	tail := in.Tail
	if tail <= 0 || tail > 50 {
		tail = 5
	}
	out := LogsOut{}
	for i := range tail {
		out.Lines = append(out.Lines, fmt.Sprintf("%s/%s line %d: request served in %dms", in.Namespace, in.Pod, i+1, 20+i))
	}
	return nil, out, nil
}

func (c *Cluster) restart(_ context.Context, _ *mcp.CallToolRequest, in DeploymentIn) (*mcp.CallToolResult, ChangeOut, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.deployment(in.Namespace, in.Deployment)
	if err != nil {
		return nil, ChangeOut{}, err
	}
	d.restarts++
	return nil, ChangeOut{Message: fmt.Sprintf("restarted %s/%s (restart #%d)", in.Namespace, in.Deployment, d.restarts)}, nil
}

func (c *Cluster) scale(_ context.Context, _ *mcp.CallToolRequest, in ScaleIn) (*mcp.CallToolResult, ChangeOut, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.deployment(in.Namespace, in.Deployment)
	if err != nil {
		return nil, ChangeOut{}, err
	}
	if in.Replicas < 0 {
		return nil, ChangeOut{}, fmt.Errorf("replicas must be 0 or more")
	}
	old := d.replicas
	d.replicas = in.Replicas
	return nil, ChangeOut{Message: fmt.Sprintf("scaled %s/%s from %d to %d", in.Namespace, in.Deployment, old, in.Replicas)}, nil
}

func (c *Cluster) deleteNamespace(_ context.Context, _ *mcp.CallToolRequest, in NamespaceIn) (*mcp.CallToolResult, ChangeOut, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.namespaces[in.Namespace]; !ok {
		return nil, ChangeOut{}, fmt.Errorf("namespace %q not found", in.Namespace)
	}
	delete(c.namespaces, in.Namespace)
	return nil, ChangeOut{Message: "deleted namespace " + in.Namespace}, nil
}

// ToolNames lists the demo server's tools in a stable order.
var ToolNames = []string{"delete_namespace", "get_logs", "list_pods", "restart_deployment", "scale_deployment"}

// NewServer returns an MCP server exposing the cluster's five tools.
//
// The annotations (read-only, destructive) are the server describing itself.
// The gate deliberately ignores them: a server can claim anything, so risk
// levels come from the gate operator's Cedar schema instead.
func NewServer(c *Cluster) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "demo-cluster", Version: "0.1.0"}, nil)
	yes, no := true, false
	mcp.AddTool(s, &mcp.Tool{Name: "list_pods", Description: "List the pods in a namespace.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, c.listPods)
	mcp.AddTool(s, &mcp.Tool{Name: "get_logs", Description: "Read the last lines of a pod's log.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, c.getLogs)
	mcp.AddTool(s, &mcp.Tool{Name: "restart_deployment", Description: "Restart every pod of a deployment.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no, IdempotentHint: false}}, c.restart)
	mcp.AddTool(s, &mcp.Tool{Name: "scale_deployment", Description: "Set a deployment's replica count.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no, IdempotentHint: true}}, c.scale)
	mcp.AddTool(s, &mcp.Tool{Name: "delete_namespace", Description: "Delete a namespace and everything in it.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes}}, c.deleteNamespace)
	return s
}

// Handler serves the server over MCP's Streamable HTTP transport. With
// jsonResponses, replies are plain application/json; otherwise each POST gets
// a text/event-stream. The gate must handle both, so the tests run both.
func Handler(s *mcp.Server, jsonResponses bool) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{JSONResponse: jsonResponses})
}

// Describe is a one-line summary used by the demo server's startup log.
func Describe() string { return "tools: " + strings.Join(ToolNames, ", ") }
