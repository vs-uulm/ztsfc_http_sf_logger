package config

import (
	"crypto/tls"
	"crypto/x509"
)

// The SysLoggerT struct defines system logger main attributes:
// Logging level, destination to write the log messages, and the messages format
type SysLoggerT struct {
	LogLevel     string `yaml:"system_logger_logging_level"`
	LogFilePath  string `yaml:"system_logger_destination"`
	LogFormatter string `yaml:"system_logger_format"`
}

// The struct CertSetT defines a set of a x509 certificate, corresponding private key
// and a CA for validating certificates, that are shown to the service function
type CertSetT struct {
	Cert_shown_by_sf             string `yaml:"cert_shown_by_sf"`
	Privkey_for_cert_shown_by_sf string `yaml:"privkey_for_cert_shown_by_sf"`
	Certs_sf_accepts             string `yaml:"certs_sf_accepts"`
}

// The struct ServiceFunctionT is for parsing the section 'sf' of the config file.
type ServiceFunctionT struct {
	ListenAddr  string   `yaml:"listen_addr"`
	ServerCerts CertSetT `yaml:"server"`
	ClientCerts CertSetT `yaml:"client"`
}

// ConfigT struct is for parsing the basic structure of the config file
type ConfigT struct {
	SysLogger                    SysLoggerT       `yaml:"system_logger"`
	SF                           ServiceFunctionT `yaml:"sf"`
	X509KeyPairShownBySFAsServer tls.Certificate
	CAcertPoolPepAcceptsFromExt  *x509.CertPool
	X509KeyPairShownBySFAsClient tls.Certificate
	CAcertPoolPepAcceptsFromInt  *x509.CertPool
}

// Config contains all input from the config file and is is globally accessible
var Config ConfigT
