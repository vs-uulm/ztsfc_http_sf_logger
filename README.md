# ztsfc_http_sf_logger
A service function that can log HTTP packets using dynamic logging levels.

## Parameters
### Path to the config file
Syntax: `-c <path_to_config_file>`

Type: required.

Default value: "*./config/conf.yml*"

## Configuration file
An example of the configuration file is in the config directory. Simply copy it:

`cp config/example_conf.yml config/conf.yml`

and adjust the values to your needs.

## HTTP requests logging levels
The next three main logging levels are implemented: `"basic", "advanced", "full"`.

The "**basic**" level prints general packet info including the packet header values.

The "**advanced**" adds to the previous level form(s) value(s) and transferring file(s) contents.

The "**full**" level outputs all previous information and the packet body.

The SF Logger gets the logging level value in the "**Logger_MD**" HTTP header and deletes the header before the packet forwarding to the next SF in the chain or to a target service.
