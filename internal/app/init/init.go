// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_conf.yml corresponds to a function of this package.
package init

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
)

// InitSysLoggerParams() sets the default values for a system logger
func InitSysLoggerParams() {
	// Set a default logging level.
	// The level "info" is necessary to see the messages
	// of http.Server and httputil.ReverseProxy ErrorLogs.
	if config.Config.SysLogger.LogLevel == "" {
		config.Config.SysLogger.LogLevel = "info"
	}

	// Set a default log messages destination
	if config.Config.SysLogger.LogFilePath == "" {
		config.Config.SysLogger.LogFilePath = "stdout"
	}

	// Set a default log messages JSON formatter
	if config.Config.SysLogger.LogFormatter == "" {
		config.Config.SysLogger.LogFormatter = "json"
	}
}

// Function initializes the 'sf' section of the config file
// and loads the SF certificates.
func InitServFuncParams(sysLogger *logger.Logger) error {
	var err error
	fields := ""

	if (config.Config.SF == config.ServiceFunctionT{}) {
		return fmt.Errorf("init: InitServFuncParams(): the section 'sf' is empty. No service function parameters are defined")
	}

	if config.Config.SF.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if (config.Config.SF.ServerCerts == config.CertSetT{}) {
		fields += "listen_addr,server.cert_shown_by_sf,server.privkey_for_cert_shown_by_sf,server.cert_sf_accepts_shown_by_incoming_connections,"
	} else {
		if config.Config.SF.ServerCerts.Cert_shown_by_sf == "" {
			fields += "server.cert_shown_by_sf,"
		}
		if config.Config.SF.ServerCerts.Privkey_for_cert_shown_by_sf == "" {
			fields += "server.privkey_for_cert_shown_by_sf,"
		}
		if config.Config.SF.ServerCerts.Certs_sf_accepts == "" {
			fields += "server.cert_sf_accepts_shown_by_incoming_connections,"
		}
	}

	if (config.Config.SF.ClientCerts == config.CertSetT{}) {
		fields += "listen_addr,client.cert_shown_by_sf,client.privkey_for_cert_shown_by_sf,client.cert_sf_accepts_shown_by_incoming_connections,"
	} else {
		if config.Config.SF.ClientCerts.Cert_shown_by_sf == "" {
			fields += "client.cert_shown_by_sf,"
		}
		if config.Config.SF.ClientCerts.Privkey_for_cert_shown_by_sf == "" {
			fields += "client.privkey_for_cert_shown_by_sf,"
		}
		if config.Config.SF.ClientCerts.Certs_sf_accepts == "" {
			fields += "client.cert_sf_accepts_shown_by_incoming_connections,"
		}
	}

	if fields != "" {
		return fmt.Errorf("init: InitServFuncParams(): in the section 'sf' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Preload SF X509KeyPair when it acts as a server and write it to config
	config.Config.X509KeyPairShownBySFAsServer, err = loadX509KeyPair(sysLogger,
		config.Config.SF.ServerCerts.Cert_shown_by_sf, config.Config.SF.ServerCerts.Privkey_for_cert_shown_by_sf, "service", "")
	if err != nil {
		return err
	}

	// Preload CA certificate to verify certificates of incoming connections and write it to config
	err = loadCACertificate(sysLogger, config.Config.SF.ServerCerts.Certs_sf_accepts, "service", config.Config.CAcertPoolPepAcceptsFromExt)
	if err != nil {
		return err
	}

	// Preload SF X509KeyPair when it acts as a client and write it to config
	config.Config.X509KeyPairShownBySFAsClient, err = loadX509KeyPair(sysLogger,
		config.Config.SF.ClientCerts.Cert_shown_by_sf, config.Config.SF.ClientCerts.Privkey_for_cert_shown_by_sf, "service", "")
	if err != nil {
		return err
	}

	// Preload CA certificate to verify certificates of outgoing connections and write it to config
	err = loadCACertificate(sysLogger, config.Config.SF.ClientCerts.Certs_sf_accepts, "service", config.Config.CAcertPoolPepAcceptsFromInt)
	if err != nil {
		return err
	}

	return nil
}

// LoadX509KeyPair() unifies the loading of X509 key pairs for different components
func loadX509KeyPair(sysLogger *logger.Logger, certfile, keyfile, componentName, certAttr string) (tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("init: loadX509KeyPair(): loading %s X509KeyPair for %s from %s and %s - FAIL: %v",
			certAttr, componentName, certfile, keyfile, err)
	}
	sysLogger.Debugf("init: loadX509KeyPair(): loading %s X509KeyPair for %s from %s and %s - OK", certAttr, componentName, certfile, keyfile)
	return keyPair, nil
}

// function unifies the loading of CA certificates for different components
func loadCACertificate(sysLogger *logger.Logger, certfile string, componentName string, certPool *x509.CertPool) error {
	// Read the certificate file content
	caRoot, err := ioutil.ReadFile(certfile)
	if err != nil {
		return fmt.Errorf("init: loadCACertificate(): loading %s CA certificate from '%s' - FAIL: %w", componentName, certfile, err)
	}
	sysLogger.Debugf("init: loadCACertificate(): loading %s CA certificate from '%s' - OK", componentName, certfile)

	// Return error if provided certificate is nil
	if certPool == nil {
		return errors.New("provided certPool is nil")
	}

	// Append a certificate to the pool
	certPool.AppendCertsFromPEM(caRoot)
	return nil
}

func SetupCloseHandler(logger *logger.Logger) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Debug("- 'Ctrl + C' was pressed in the Terminal. Terminating...")
		logger.Terminate()
		os.Exit(0)
	}()
}
