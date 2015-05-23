package backend

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

type File struct {
	Path string
}

func (f *File) Connect() error {
	dirs := []string{filepath.Join(f.Path, "certs"), filepath.Join(f.Path, "keys")}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0700); err != nil && !os.IsExist(err) {
				return fmt.Errorf("Could not create %s directory %s", dir, err)
			}
		}
	}

	return nil
}

// checks

func (f *File) CheckCertificateExists(name string) bool {
	return fileExists(f.certPath(name))
}

func (f *File) CheckCertificateValid(name string) bool {
	return true
}

func (f *File) CheckPrivateKeyExists(name string) bool {
	return fileExists(f.keyPath(name))
}

// gets

func (f *File) CreateTokenForCertificate(name string) (string, error) {
	return "", nil
}

func (f *File) GetConfig() (string, error) {
	bytes, err := f.readFile(f.configPath())
	if err != nil {
		log.Println("error:", err)
		return "", err
	}
	return string(bytes), err
}

func (f *File) GetCertificate(name string) (*x509.Certificate, error) {
	bytes, err := f.readFile(f.certPath(name))
	if err != nil {
		log.Println("error:", err)
		return nil, err
	}
	data, _ := pem.Decode([]byte(bytes))
	cert, _ := x509.ParseCertificate(data.Bytes)
	return cert, nil
}

func (f *File) GetCRLRaw() []byte {
	bytes, err := f.readFile(f.crlPath())
	if err != nil && os.IsExist(err) {
		return nil
	}
	return bytes
}

func (f *File) GetNextSerialNumber() *big.Int {
	curr := big.NewInt(1)
	bytes, err := f.readFile(f.serialNumberPath())
	if err != nil && os.IsExist(err) {
		return curr
	}
	if len(bytes) != 0 {
		curr = new(big.Int)
		curr.UnmarshalText(bytes)
		curr.Add(curr, big.NewInt(1))
	}

	bytes, _ = curr.MarshalText()
	_ = f.writeFileRaw(f.serialNumberPath(), bytes)
	return curr
}

func (f *File) GetPrivateKey(name string) (*rsa.PrivateKey, error) {
	bytes, err := f.readFile(f.keyPath(name))
	if err != nil {
		log.Println("error:", err)
		return nil, err
	}

	data, _ := pem.Decode([]byte(bytes))
	key, _ := x509.ParsePKCS1PrivateKey(data.Bytes)
	return key, nil
}

// puts

func (f *File) PutConfig(config string) error {
	return f.writeFileRaw(f.configPath(), []byte(config))
}

func (f *File) PutCertificate(name string, cert *x509.Certificate) error {
	return f.writeFile("CERTIFICATE", f.certPath(name), cert.Raw)
}

func (f *File) PutPrivateKey(name string, key *rsa.PrivateKey) error {
	return f.writeFile("RSA PRIVATE KEY", f.keyPath(name), x509.MarshalPKCS1PrivateKey(key))
}

func (f *File) PutCRL(crlBytes []byte) error {
	return f.writeFileRaw(f.crlPath(), crlBytes)
}

// private functionality

func (f *File) crlPath() string {
	return filepath.Join(f.Path, "crl.crl")
}

func (f *File) serialNumberPath() string {
	return filepath.Join(f.Path, "SERIAL")
}

func (f *File) certPath(name string) string {
	return filepath.Join(f.certsDir(), fmt.Sprintf("%s.crt", name))
}

func (f *File) keyPath(name string) string {
	return filepath.Join(f.keysDir(), fmt.Sprintf("%s.key", name))
}

func (f *File) certsDir() string {
	return filepath.Join(f.Path, "certs")
}

func (f *File) keysDir() string {
	return filepath.Join(f.Path, "keys")
}

func (f *File) configPath() string {
	return filepath.Join(f.Path, "config")
}

func (f *File) readFile(path string) ([]byte, error) {
	fileIn, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	info, err := fileIn.Stat()
	if err != nil {
		return nil, err
	}

	var size int64 = info.Size()
	bytes := make([]byte, size)

	buffer := bufio.NewReader(fileIn)
	_, err = buffer.Read(bytes)
	if err != nil {
		return nil, err
	}

	fileIn.Close()
	return bytes, nil

}

func (f *File) writeFileRaw(path string, data []byte) error {
	fileOut, err := os.Create(path)
	if err != nil {
		log.Println("failed to open file for writing", err)
		return err
	}
	fileOut.Write(data)
	fileOut.Close()
	return nil
}

func (f *File) writeFile(ttype string, path string, data []byte) error {
	fileOut, err := os.Create(path)
	if err != nil {
		log.Println("failed to open file for writing", err)
		return err
	}
	pem.Encode(fileOut, &pem.Block{
		Type:  ttype,
		Bytes: data,
	})
	fileOut.Close()
	return nil
}

func fileExists(path string) bool {
	fileIn, err := os.Open(path)
	if err != nil {
		return false
	}

	_, err = fileIn.Stat()
	if err != nil {
		return false
	}

	return true
}
