package env

import (
    "os"
    "gopkg.in/yaml.v2"
)

type Certificates_set_t struct {
  Cert_shown_by_sf              string `yaml:"cert_shown_by_sf"`
  Privkey_for_cert_shown_by_sf  string `yaml:"privkey_for_cert_shown_by_sf"`
  Certs_sf_accepts              string `yaml:"certs_sf_accepts"`
}

type Sf_t struct {
  Listen_addr   string              `yaml:"listen_addr"`
  Server        Certificates_set_t  `yaml:"server"`
  Client        Certificates_set_t  `yaml:"client"`
}

type Config_t struct {
  Sf Sf_t `yaml:"sf"`
}

var Config Config_t

// Parses a configuration yaml file into the global Config variable
func LoadConfig(configPath string) (err error) {
    // Open config file
    file, err := os.Open(configPath)
    if err != nil {
        return
    }
    defer file.Close()
    
    // Init new YAML decode
    d := yaml.NewDecoder(file)

    // Start YAML decoding from file
    err = d.Decode(&Config)
    return
}