package env

import (
	"gopkg.in/yaml.v2"
	logwriter "local.com/leobrada/ztsfc_http_sf_logger/logwriter"
	"os"
)

type Certificates_set_t struct {
	Cert_shown_by_sf             string `yaml:"cert_shown_by_sf"`
	Privkey_for_cert_shown_by_sf string `yaml:"privkey_for_cert_shown_by_sf"`
	Certs_sf_accepts             string `yaml:"certs_sf_accepts"`
}

type Sf_t struct {
	Listen_addr string             `yaml:"listen_addr"`
	Server      Certificates_set_t `yaml:"server"`
	Client      Certificates_set_t `yaml:"client"`
}

type Config_t struct {
	Sf Sf_t `yaml:"sf"`
}

var Config Config_t

// Parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string, lw *logwriter.LogWriter) (err error) {
	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		lw.Logger.Fatalf("Open configuration file error: %v", err)
	} else {
		lw.Logger.Debugf("Configuration file %s exists and is readable", configPath)
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	err = d.Decode(&Config)
	if err != nil {
		lw.Logger.Fatalf("Configuration yaml-->go decoding error: %v", err)
	} else {
		lw.Logger.Debugf("Configuration has been successfully decoded")
	}

	return
}
