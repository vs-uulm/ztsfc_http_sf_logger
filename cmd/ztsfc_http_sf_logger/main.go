package main

import (
	"flag"
	"log"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
	confInit "github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/router"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/yaml"
)

var (
	sysLogger    *logger.Logger
	confFilePath string
)

func init() {
	var err error

	// Parsing command line parameters
	flag.StringVar(&confFilePath, "c", "", "Path to user defined yml config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = yaml.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatal(err)
	}

	// Create an instance of the system logger
	confInit.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.LogFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		log.Fatal(err)
	}
	confInit.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from '%s' - OK", confFilePath)

	// sf
	err = confInit.InitServFuncParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}
}

func main() {
	// Create a new instance of the HTTP Logger service function
	httpLoggerSF, err := router.New(sysLogger)
	if err != nil {
		sysLogger.Error(err)
		return
	}
	sysLogger.Debug("main: main(): new router is successfully created")

	http.Handle("/", httpLoggerSF)

	err = httpLoggerSF.ListenAndServeTLS()
	if err != nil {
		sysLogger.Error(err)
	}
}
