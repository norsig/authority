package config

import (
	"strings"
	"testing"
)

var cfgStr = `
[defaults]
  root_domain = "ovrclk.com"
  email = "jeff@ovrclk.com"
  org = "ovrclk"
  org_unit = "Computers"
  city = "Missoula"
  region = "Montana"
  country = "USA"
  crl_days = "365"
  digest = "sha256"
  cert_expiry = "365"
`

func TestParseConfig(t *testing.T) {
	config, err := OpenConfig(cfgStr)
	if err != nil {
		t.Fatal("problem parsing config: %v", err)
	}

	if config.Defaults.RootDomain != "ovrclk.com" {
		t.Fatal("got unexpected config values")
	}
}

func TestDumpConfig(t *testing.T) {
	config := &Config{
		Defaults: DefaultsConfig{
			RootDomain: "ovrclk.com",
		},
	}

	str, err := config.ToString()
	if err != nil {
		t.Fatal("problem encoding config: %v", err)
	}

	if !strings.Contains(str, `root_domain = "ovrclk.com"`) {
		t.Fatal("got unexpected config values")
	}
}
