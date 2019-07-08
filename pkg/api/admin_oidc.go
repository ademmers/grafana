package api

import (
	"github.com/grafana/grafana/pkg/services/oidc"
)

func (server *HTTPServer) ReloadOIDCCfg() Response {
	err := oidc.ReloadConfig()
	if err != nil {
		return Error(500, "Failed to reload oidc config.", err)
	}
	return Success("OIDC config reloaded")
}
