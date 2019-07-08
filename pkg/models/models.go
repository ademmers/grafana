package models

type OAuthType int

const (
	GITHUB OAuthType = iota + 1
	GOOGLE
	TWITTER
	GENERIC
	OIDC
	GRAFANA_COM
	GITLAB
)
