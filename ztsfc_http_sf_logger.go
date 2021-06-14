package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	env "local.com/leobrada/ztsfc_http_sf_logger/env"
	logwriter "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
	router "local.com/leobrada/ztsfc_http_sf_logger/router"
	service_function "local.com/leobrada/ztsfc_http_sf_logger/service_function"

//    "github.com/pkg/profile"
)

var (
	conf_file_path     string
	log_file_path      string
	log_level          string
	http_log_file_path string
	ifTextFormatter    bool

	// An instance of logrus logger
	lw *logwriter.LogWriter
)

func init() {
	flag.StringVar(&log_file_path, "log-to", "./system.log", "Path to log file")
	flag.StringVar(&http_log_file_path, "http-log-to", "./http.log", "Path to log file for incoming HTTP requests")
	flag.StringVar(&conf_file_path, "conf", "./conf.yml", "Path to user defined yml config file")
	flag.StringVar(&log_level, "log-level", "error", "Log level from the next set: debug, info, warning, error")
	flag.BoolVar(&ifTextFormatter, "text", false, "Use a text format instead of JSON to log messages")

	// Operating input parameters
	flag.Parse()

	lw = logwriter.New(log_file_path, log_level, ifTextFormatter)
	//SetupCloseHandler(lw)

	err := env.LoadConfig(conf_file_path, lw)
	if err != nil {
		lw.Logger.Fatalf("Fatal Error during loading logger configuration from %s: %v", conf_file_path, err)
	} else {
		lw.Logger.Debugf("Logger configuration is successfully loaded from %s", conf_file_path)
	}
}

func main() {
//    defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()

	// Create Zero Trust Service Function
	sf_logger := service_function.NewServiceFunction()
	sf_logger.SetHttpLogFileName(http_log_file_path)
	sf_logger.RunHttpLogger()

	router, err := router.NewRouter(sf_logger, lw)
	if err != nil {
		lw.Logger.Fatalf("Fatal error during new router creation: %v", err)
	} else {
		lw.Logger.Debug("New router is successfully created")
	}

	http.Handle("/", router)

	err = router.ListenAndServeTLS()
	if err != nil {
		lw.Logger.Fatalf("ListenAndServeTLS Fatal Error: %v", err)
	}
}

func SetupCloseHandler(lw *logwriter.LogWriter) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		lw.Logger.Debug("- Ctrl+C pressed in Terminal. Terminating...")
		lw.Terminate()
		os.Exit(0)
	}()
}
