package main

import (
    // "fmt"
    "log"
    "flag"
    "net/http"

    env              "local.com/leobrada/ztsfc_http_sf_logger/env"
    router           "local.com/leobrada/ztsfc_http_sf_logger/router"
    service_function "local.com/leobrada/ztsfc_http_sf_logger/service_function"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
    sf_logger_dest = flag.Bool("log-to-file", false, "Redirect the logger output to a file")
    self_log_level = flag.Int("l", 0, "Log level")
)

func init() {
    flag.Parse()

    err := env.LoadConfig(*conf_file_path)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    // Create Zero Trust Service Function
    sf_logger := service_function.NewServiceFunction()
    
    sf_logger.SetOptions(*sf_logger_dest)
    
    router, err := router.NewRouter(sf_logger, *self_log_level)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    router.Log(1, "Listening on port", env.Config.Sf.Listen_addr)
    err = router.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
