package config

import (
	"bytes"
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
		return nil, fmt.Errorf("authority: invalid config %v", err)
	}
	return c, nil
}

// Dump configuration to a TOML string.
func (c *Config) ToString() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(c); err != nil {
		return "", fmt.Errorf("authority: cannot encode configuration: %v", err)
	}
	return buf.String(), nil
}
