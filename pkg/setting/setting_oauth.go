package setting

type OAuthInfo struct {
	ClientId, ClientSecret       string
	Scopes                       []string
	AuthUrl, TokenUrl            string
	Enabled                      bool
	EmailAttributeName           string
	UsernameAttributeName        string
	DisplaynameAttributeName     string
	RoleAttributeName            string
	AllowedDomains               []string
	HostedDomain                 string
	ApiUrl                       string
	AllowSignup                  bool
	Name                         string
	TlsClientCert                string
	TlsClientKey                 string
	TlsClientCa                  string
	TlsSkipVerify                bool
	SendClientCredentialsViaPost bool
	OIDCConfigFile               string
	AllowNoOrgRolesLogin         bool
}

type OAuther struct {
	OAuthInfos map[string]*OAuthInfo
}

var OAuthService *OAuther
