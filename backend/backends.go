package backend

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/ovrclk/authority/config"
)

// Interface for storing authority configuration information, as well as
// generated certificates and keys.
type Backend interface {
	Connect() error

	// checks
	CheckCertificateExists(name string) bool
	CheckPrivateKeyExists(name string) bool

	// gets
	CreateTokenForCertificate(name string) (string, error)
	GetConfig() (*config.Config, error)
	GetCertificate(name string) (*x509.Certificate, error)
	GetCRLRaw(name string) []byte
	GetNextSerialNumber() *big.Int
	GetPrivateKey(name string) (*rsa.PrivateKey, error)

	// puts
	PutConfig(config string) error
	PutCertificate(name string, cert *x509.Certificate) error
	PutPrivateKey(name string, key *rsa.PrivateKey) error
	PutCRL(name string, crlBytes []byte) error
}
