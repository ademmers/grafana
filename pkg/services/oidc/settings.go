package oidc

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/errutil"
)

// Config holds list of connections to OIDC
type Config struct {
	Scopes []*ScopeToRole `toml:"scope_mappings"`
}

// ScopeToRole is a struct representation of
// config "scope_mappings" setting
type ScopeToRole struct {
	Scope          string          `toml:"scope"`
	OrgID          int64           `toml:"org_id"`
	TeamIDs        []int64         `toml:"team_ids"`
	IsGrafanaAdmin *bool           `toml:"grafana_admin"`
	OrgRole        models.RoleType `toml:"org_role"`
}

// logger for all OIDC stuff
var logger = log.New("oidc")

// loadingMutex locks the reading of the config so multiple requests for reloading are sequential.
var loadingMutex = &sync.Mutex{}

func IsEnabled() bool {
	return setting.OAuthService.OAuthInfos["oidc"].Enabled
}

// ReloadConfig reads the config from the disc and caches it.
func ReloadConfig() error {
	if !IsEnabled() {
		return nil
	}

	loadingMutex.Lock()
	defer loadingMutex.Unlock()

	var err error
	config, err = readConfig(setting.OAuthService.OAuthInfos["oidc"].OIDCConfigFile)
	return err
}

// We need to define in this space so `GetConfig` fn
// could be defined as singleton
var config *Config

// GetConfig returns the OIDC config if OIDC is enabled otherwise it returns nil. It returns either cached value of
// the config or it reads it and caches it first.
func GetConfig() (*Config, error) {
	if !IsEnabled() {
		return nil, nil
	}

	// Make it a singleton
	if config != nil {
		return config, nil
	}

	loadingMutex.Lock()
	defer loadingMutex.Unlock()

	var err error
	config, err = readConfig(setting.OAuthService.OAuthInfos["oidc"].OIDCConfigFile)

	return config, err
}

func readConfig(configFile string) (*Config, error) {
	result := &Config{}

	logger.Info("OIDC enabled, reading config file", "file", configFile)

	_, err := toml.DecodeFile(configFile, result)
	if err != nil {
		return nil, errutil.Wrap("Failed to load OIDC config file", err)
	}

	// set default org id
	for _, scope := range result.Scopes {
		err = assertNotEmptyCfg(scope.Scope, "scope")
		if err != nil {
			return nil, errutil.Wrap("Failed to validate scope section", err)
		}

		err = assertNotEmptyCfg(scope.OrgRole, "org_role")
		if err != nil {
			return nil, errutil.Wrap("Failed to validate org_role section", err)
		}

		if scope.OrgID == 0 {
			scope.OrgID = 1
		}
	}

	return result, nil
}

func assertNotEmptyCfg(val interface{}, propName string) error {
	switch v := val.(type) {
	case string:
		if v == "" {
			return xerrors.Errorf("OIDC config file is missing option: %v", propName)
		}
	case []string:
		if len(v) == 0 {
			return xerrors.Errorf("OIDC config file is missing option: %v", propName)
		}
	default:
		fmt.Println("unknown")
	}
	return nil
}

func GetOrgRolesFromScopes(scopes []string) (map[int64][]int64, map[int64]models.RoleType, *bool) {
	orgRoles := make(map[int64]models.RoleType)
	isGrafanaAdmin := &[]bool{false}[0]
	teams := make(map[int64][]int64)

	if config == nil {
		GetConfig()
	}

	for _, configedScope := range config.Scopes {
		for _, tokenScopeName := range scopes {
			if tokenScopeName == configedScope.Scope {
				orgRoles[configedScope.OrgID] = configedScope.OrgRole
				if configedScope.IsGrafanaAdmin != nil {
					isGrafanaAdmin = configedScope.IsGrafanaAdmin
				}
				if configedScope.TeamIDs != nil {
					if orgTeams, ok := teams[configedScope.OrgID]; ok {
						teams[configedScope.OrgID] = append(orgTeams, configedScope.TeamIDs...)
					} else {
						teams[configedScope.OrgID] = append(make([]int64, 0), configedScope.TeamIDs...)
					}
				}
			}
		}
	}

	return teams, orgRoles, isGrafanaAdmin
}
