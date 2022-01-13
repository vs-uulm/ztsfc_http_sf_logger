package service_function

import (
	"net/http"
)

type ServiceFunction interface {
	ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
	GetSFName() (name string)
}
