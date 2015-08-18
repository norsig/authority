package authority

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config provides a structure to read x509 certificate configuration
// information from TOML.
type Config struct {
	Defaults DefaultsConfig `toml:"defaults"`
}

type DefaultsConfig struct {
	RootDomain string `toml:"root_domain"`
	Email      string `toml:"email"`
	Org        string `toml:"org"`
	OrgUnit    string `toml:"org_unit"`
	City       string `toml:"city"`
	Region     string `toml:"region"`
	Country    string `toml:"country"`
	CrlDays    string `toml:"crl_days"`
	Digest     string `toml:"digest"`
	CertExpiry string `toml:"cert_expiry"`
}

// Load the provided TOML configuration into a Config struct.
func OpenConfig(config string) (*Config, error) {
	c := &Config{}
	if _, err := toml.Decode(config, c); err != nil {
		return nil, fmt.Errorf("invalid config: %s", err)
	}
	return c, nil
}
