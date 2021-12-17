package httplogger

import (
	"github.com/sirupsen/logrus"
	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
)

type HTTPLogger struct {
	sysLogger *logger.Logger
}

// New() creates a new instance of the HTTP Logger
func New() (*HTTPLogger, error) {
	// Create an instance of the system logger
	sysLogger, err := logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.LogFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		logrus.Error("unable to create a logger instance")
		return nil, err
	}

	return &HTTPLogger{
		sysLogger: sysLogger,
	}, nil
}

// Start() configures and runs the HTTP logger
func (l *HTTPLogger) Start() error {

	// Start the HTTP logger

	return nil
}
