package config

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

var configKeys = []string{"root_domain",
	"email",
	"org",
	"org_unit",
	"city",
	"region",
	"country",
	"crl_days",
	"digest",
	"cert_expiry"}

// Returns whether or not the provided key is a valid configuration item.
func KeyIsValid(key string) bool {
	for _, v := range configKeys {
		if v == key {
			return true
		}
	}
	return false
}

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

func (c *Config) SetItem(item, value string) {
	switch item {
	case "root_domain":
		c.Defaults.RootDomain = value
	case "email":
		c.Defaults.Email = value
	case "org":
		c.Defaults.Org = value
	case "org_unit":
		c.Defaults.OrgUnit = value
	case "city":
		c.Defaults.City = value
	case "region":
		c.Defaults.Region = value
	case "country":
		c.Defaults.Country = value
	case "crl_days":
		c.Defaults.CrlDays = value
	case "digest":
		c.Defaults.Digest = value
	case "cert_expiry":
		c.Defaults.CertExpiry = value
	}
}

func (c *Config) GetItem(item string) string {
	switch item {
	case "root_domain":
		return c.Defaults.RootDomain
	case "email":
		return c.Defaults.Email
	case "org":
		return c.Defaults.Org
	case "org_unit":
		return c.Defaults.OrgUnit
	case "city":
		return c.Defaults.City
	case "region":
		return c.Defaults.Region
	case "country":
		return c.Defaults.Country
	case "crl_days":
		return c.Defaults.CrlDays
	case "digest":
		return c.Defaults.Digest
	case "cert_expiry":
		return c.Defaults.CertExpiry
	}
	return ""
}

// Dump configuration to a TOML string.
func (c *Config) ToString() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(c); err != nil {
		return "", fmt.Errorf("authority: cannot encode configuration: %v", err)
	}
	return buf.String(), nil
}

// Returns a list of valid configuration keys.
func (c *Config) GetConfigKeys() []string {
	return configKeys
}
