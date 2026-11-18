package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedConfigLoads(t *testing.T) {
	c, err := Load("../../gate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Agents) != 3 || c.Location.String() != "Asia/Kolkata" || c.UpstreamURL.Host != "127.0.0.1:8090" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if !filepath.IsAbs(c.Policies.Dir) && !strings.HasSuffix(filepath.ToSlash(c.Policies.Dir), "policies") {
		t.Fatalf("policies dir %q", c.Policies.Dir)
	}
}

func TestBadConfigs(t *testing.T) {
	good := `upstream: {url: "http://127.0.0.1:8090/mcp"}
policies: {dir: policies}
agents:
  - {id: a, teams: [sre], token_sha256: 207adcf67f95065adb33a50b488cf7d7bcff7c63704543046cb84ac98242558d}
`
	cases := map[string]struct{ body, want string }{
		"misspelt key":     {strings.Replace(good, "policies:", "polices:", 1), "polices"},
		"no agents":        {"upstream: {url: \"http://x/mcp\"}\npolicies: {dir: p}\n", "no agents"},
		"plain token":      {strings.Replace(good, "207adcf67f95065adb33a50b488cf7d7bcff7c63704543046cb84ac98242558d", "demo-oncall-token", 1), "64 lowercase hex"},
		"uppercase hash":   {strings.Replace(good, "207adcf67f", "207ADCF67F", 1), "64 lowercase hex"},
		"bad upstream":     {strings.Replace(good, "http://127.0.0.1:8090/mcp", "ftp://x", 1), "http or https"},
		"unknown timezone": {good + "time_zone: Mars/Olympus\n", "time_zone"},
		"shared token": {good + "  - {id: b, token_sha256: 207adcf67f95065adb33a50b488cf7d7bcff7c63704543046cb84ac98242558d}\n",
			"share a token"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "gate.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
