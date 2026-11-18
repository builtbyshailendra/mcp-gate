// Package config reads mcp-gate's YAML config.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/builtbyshailendra/mcp-gate/internal/authz"
)

// Agent is one agent and the hash of its bearer token.
type Agent struct {
	authz.Agent `yaml:",inline"`
	TokenSHA256 string `yaml:"token_sha256"`
}

// Config is the whole file.
type Config struct {
	Listen      string `yaml:"listen"`
	AdminListen string `yaml:"admin_listen"`
	Upstream    struct {
		Name     string `yaml:"name"`
		URL      string `yaml:"url"`
		TokenEnv string `yaml:"token_env"` // env var holding the gate's own upstream token, if any
	} `yaml:"upstream"`
	Policies struct {
		Dir         string        `yaml:"dir"`
		ReloadEvery time.Duration `yaml:"reload_every"`
	} `yaml:"policies"`
	TimeZone     string   `yaml:"time_zone"`
	MaxBodyBytes int64    `yaml:"max_body_bytes"`
	AuditLog     string   `yaml:"audit_log"` // a file path, or "-" for stdout
	ExtraMethods []string `yaml:"extra_methods"`
	Agents       []Agent  `yaml:"agents"`

	// Set by Load.
	Location    *time.Location `yaml:"-"`
	UpstreamURL *url.URL       `yaml:"-"`
}

// Load reads and checks a config file. Relative paths in it are relative to
// the file's own directory.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a misspelt key is an error, not a silent default
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8081"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:9091"
	}
	if c.Upstream.Name == "" {
		c.Upstream.Name = "upstream"
	}
	u, err := url.Parse(c.Upstream.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("upstream.url %q must be an http or https URL", c.Upstream.URL)
	}
	c.UpstreamURL = u
	if c.Policies.Dir == "" {
		return nil, errors.New("policies.dir is required")
	}
	if !filepath.IsAbs(c.Policies.Dir) {
		c.Policies.Dir = filepath.Join(base, c.Policies.Dir)
	}
	if c.Policies.ReloadEvery == 0 {
		c.Policies.ReloadEvery = 2 * time.Second
	}
	if c.AuditLog != "" && c.AuditLog != "-" && !filepath.IsAbs(c.AuditLog) {
		c.AuditLog = filepath.Join(base, c.AuditLog)
	}
	if c.TimeZone == "" {
		c.TimeZone = "UTC"
	}
	if c.Location, err = time.LoadLocation(c.TimeZone); err != nil {
		return nil, fmt.Errorf("time_zone: %w", err)
	}
	if len(c.Agents) == 0 {
		return nil, errors.New("no agents: nobody could use the gate")
	}
	seen := map[string]string{}
	for _, a := range c.Agents {
		if a.ID == "" {
			return nil, errors.New("an agent has no id")
		}
		b, err := hex.DecodeString(a.TokenSHA256)
		if err != nil || len(b) != 32 || a.TokenSHA256 != hex.EncodeToString(b) {
			return nil, fmt.Errorf("agent %q: token_sha256 must be 64 lowercase hex characters (use: mcp-gate hash-token)", a.ID)
		}
		if other, dup := seen[a.TokenSHA256]; dup {
			return nil, fmt.Errorf("agents %q and %q share a token", other, a.ID)
		}
		seen[a.TokenSHA256] = a.ID
	}
	return &c, nil
}

// AuthzAgents is the agent list without tokens.
func (c *Config) AuthzAgents() []authz.Agent {
	out := make([]authz.Agent, 0, len(c.Agents))
	for _, a := range c.Agents {
		out = append(out, a.Agent)
	}
	return out
}

// Tokens maps token hash to agent ID.
func (c *Config) Tokens() map[string]string {
	out := map[string]string{}
	for _, a := range c.Agents {
		out[a.TokenSHA256] = a.ID
	}
	return out
}
