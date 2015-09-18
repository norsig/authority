package util

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

func GetCertificateFromPEM(data string) (*x509.Certificate, error) {
	return GetCertificateFromPEMBytes([]byte(data))
}

func GetCertificateFromPEMBytes(bytes []byte) (*x509.Certificate, error) {
	pem, _ := pem.Decode(bytes)
	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("authority: unable to parse certificate %v", err)
	}
	return cert, nil
}

func GetKeyFromPEM(data string) (*rsa.PrivateKey, error) {
	return GetKeyFromPEMBytes([]byte(data))
}

func GetKeyFromPEMBytes(bytes []byte) (*rsa.PrivateKey, error) {
	pem, _ := pem.Decode(bytes)
	key, err := x509.ParsePKCS1PrivateKey(pem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("authority: unable to parse private key %v", err)
	}
	return key, nil
}

func GetPEMFromCertificate(cert *x509.Certificate) string {
	return string(GetPEMBytesFromCertificate(cert))
}

func GetPEMBytesFromCertificate(cert *x509.Certificate) []byte {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return bytes
}

func GetPEMFromKey(key *rsa.PrivateKey) string {
	return string(GetPEMBytesFromKey(key))
}

func GetPEMBytesFromKey(key *rsa.PrivateKey) []byte {
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return bytes
}

func GetPEMFromCRL(c *pkix.CertificateList) string {
	if c == nil {
		return ""
	}
	bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: c.TBSCertList.Raw,
	})
	return string(bytes)
}
