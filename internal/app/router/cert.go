package router

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
)

func makeCAPool(path string) (*x509.CertPool, error) {
	// Create a new CA pool
	ca_cert_pool := x509.NewCertPool()

	// Read the CA certificate from a file
	ca_cert, err := ioutil.ReadFile(path)
	if err != nil {
		return ca_cert_pool, fmt.Errorf("router: makeCAPool(): unable to read CA certificate from '%s': %w", path, err)
	}

	// Parsing a series of PEM encoded certificates.
	ok := ca_cert_pool.AppendCertsFromPEM(ca_cert)
	if !ok {
		return ca_cert_pool, errors.New("router: makeCAPool(): appending certificate(s) to a CA certPool error")
	}

	return ca_cert_pool, nil
}
