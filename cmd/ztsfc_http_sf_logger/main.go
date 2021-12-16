package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/config"
	confInit "github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_sf_logger/internal/app/router"
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
	err = config.LoadConfig(confFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// Create an instance of the system logger
	confInit.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.IfTextFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		log.Fatal(err)
	}
	SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading logger configuration from '%s' - OK", confFilePath)

	// sf
	err = confInit.InitServFuncParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}

}

func main() {
	// Create a new instance of the HTTP Logger service function
	httpLogger, err := router.New(sysLogger)
	if err != nil {
		log.Fatal("unable to create a config")
	}
	sysLogger.Debug("new router is successfully created")

	http.Handle("/", httpLogger)

	err = httpLogger.ListenAndServeTLS()
	if err != nil {
		sysLogger.Fatalf("ListenAndServeTLS() Fatal Error: %s", err.Error())
	}
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
