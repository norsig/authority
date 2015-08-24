package backend

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/ovrclk/authority/config"
)

// Vault based backend for storing authority configuration and generated
// certificates and keys.
type Vault struct {
	Addr   string
	Client *api.Client
	Server string
	Token  string
}

// Connect to Vault server.
func (v *Vault) Connect() error {
	config := v.insecureConfig()
	config.Address = v.Server

	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("authority: can't connect to vault %v", err)
	}
	v.Client = client
	v.Client.SetToken(v.Token)

	return nil
}

// checks

// Determine if a certificate already exists in Vault.
func (v *Vault) CheckCertificateExists(name string) bool {
	path := fmt.Sprintf("secret/authority/cert/%s", name)
	secret, err := v.Client.Logical().Read(path)
	if err != nil || secret == nil {
		return false
	}
	return true
}

// Determine if a private key already exists in Vault.
func (v *Vault) CheckPrivateKeyExists(name string) bool {
	path := fmt.Sprintf("secret/authority/key/%s", name)
	secret, err := v.Client.Logical().Read(path)
	if err != nil || secret == nil {
		return false
	}
	return true
}

// gets

// Create a Vault access token with granular permissions to only access
// the specified certificate, private key and root certificate.
func (v *Vault) CreateTokenForCertificate(name string) (string, error) {
	rules := fmt.Sprintf(`
path "secret/authority/cert" {
  policy = "read"
}
path "secret/authority/config" {
  policy = "read"
}
path "secret/authority/crl" {
  policy = "read"
}
path "secret/authority/key/%s" {
  policy = "read"
}
`, name)

	policy := fmt.Sprintf("authority_%s", name)

	err := v.Client.Sys().PutPolicy(policy, rules)
	if err != nil {
		return "", err
	}

	request := &api.TokenCreateRequest{
		NoParent:    true,
		Policies:    []string{policy},
		DisplayName: fmt.Sprintf("authority: ro token for %s", name),
	}

	secret, err := v.Client.Auth().Token().Create(request)
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, nil
}

// Load authority configuraiton information from Vault.
func (v *Vault) GetConfig() (*config.Config, error) {
	path := "secret/authority/config"
	data, err := v.getString(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open configuration, no permission")
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration does not exist, do you need to set it?")
	}

	c, err := config.OpenConfig(data)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Load a certificate from Vault.
func (v *Vault) GetCertificate(name string) (*x509.Certificate, error) {
	resp, err := v.getCertificateBytes(name)
	if err != nil {
		return nil, err
	} else {
		pem, _ := pem.Decode(resp)
		cert, _ := x509.ParseCertificate(pem.Bytes)
		return cert, nil
	}
}

// Load the root certificate revocation list from Vault.
func (v *Vault) GetCRLRaw() []byte {
	path := "secret/authority/crl"
	data, err := v.getBytes(path)
	if err != nil {
		return nil
	} else if len(data) > 0 {
		pem, _ := pem.Decode(data)
		return pem.Bytes
	} else {
		return data
	}
}

// Get the next unused serial number in sequence from Vault.
func (v *Vault) GetNextSerialNumber() *big.Int {
	curr := big.NewInt(1)
	path := "secret/authority/serial"
	data, err := v.getBytes(path)
	if err != nil {
		return curr
	}
	if len(data) != 0 {
		curr = new(big.Int)
		curr.UnmarshalText(data)
		curr.Add(curr, big.NewInt(1))
	}

	bytes, _ := curr.MarshalText()
	_ = v.putBytes(path, bytes)
	return curr
}

// Load a private key from Vault.
func (v *Vault) GetPrivateKey(name string) (*rsa.PrivateKey, error) {
	path := fmt.Sprintf("secret/authority/key/%s", name)

	data, err := v.getBytes(path)
	if err != nil {
		return nil, err
	} else {
		pem, _ := pem.Decode(data)
		key, _ := x509.ParsePKCS1PrivateKey(pem.Bytes)
		return key, nil
	}
}

// puts

// Store the provided configuration TOML markup in Vault.
func (v *Vault) PutConfig(config string) error {
	path := "secret/authority/config"
	err := v.putString(path, config)
	return err
}

// Store the provided certificate in PEM format in Vault.
func (v *Vault) PutCertificate(name string, cert *x509.Certificate) error {
	path := fmt.Sprintf("secret/authority/cert/%s", name)
	err := v.putBytes(path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	if err != nil {
		return err
	} else {
		return nil
	}
}

// Store the provided private key in PEM format in Vault.
func (v *Vault) PutPrivateKey(name string, key *rsa.PrivateKey) error {
	path := fmt.Sprintf("secret/authority/key/%s", name)
	return v.putBytes(path, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// Store the provided certificate revocation list in PEM format in Vault.
func (v *Vault) PutCRL(crlBytes []byte) error {
	path := "secret/authority/crl"
	return v.putBytes(path, pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	}))
}

// private functionality

func (v *Vault) getCertificateBytes(name string) ([]byte, error) {
	path := fmt.Sprintf("secret/authority/cert/%s", name)
	data, err := v.getBytes(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (v *Vault) putBytes(path string, data []byte) error {
	return v.putString(path, string(data))
}

func (v *Vault) putString(path string, data string) error {
	payload := map[string]interface{}{
		"value": data,
	}
	_, err := v.Client.Logical().Write(path, payload)
	if err != nil {
		return err
	}
	return nil
}

func (v *Vault) getString(path string) (string, error) {
	payload, err := v.Client.Logical().Read(path)
	if err != nil || payload == nil {
		return "", err
	} else {
		return payload.Data["value"].(string), nil
	}
}

func (v *Vault) getBytes(path string) ([]byte, error) {
	data, err := v.getString(path)
	if err != nil || data == "" {
		return nil, err
	}
	return []byte(data), nil
}

func (v *Vault) insecureConfig() *api.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	client := *http.DefaultClient
	client.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	config := &api.Config{
		Address:    v.Server,
		HttpClient: &client,
	}

	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.Address = addr
	}

	return config
}
