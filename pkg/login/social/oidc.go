package social

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/oidc"

	"golang.org/x/oauth2"
)

type SocialOIDC struct {
	*SocialBase
	allowedDomains           []string
	apiUrl                   string
	allowSignup              bool
	emailAttributeName       string
	usernameAttributeName    string
	displaynameAttributeName string
	oidcConfigFile           string
}

func (s *SocialOIDC) Type() int {
	return int(models.OIDC)
}

func (s *SocialOIDC) IsEmailAllowed(email string) bool {
	return isEmailAllowed(email, s.allowedDomains)
}

func (s *SocialOIDC) IsSignupAllowed() bool {
	return s.allowSignup
}

type OIDCUserInfoJson struct {
	Name              string                 `json:"name"`
	GivenName         string                 `json:"given_name"`
	PreferredUsername string                 `json:"preferred_username"`
	Email             string                 `json:"email"`
	X                 map[string]interface{} `json:"-"`
}

func (s *SocialOIDC) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data OIDCUserInfoJson

	if !s.extractToken(&data, token) {
		response, err := HttpGet(client, s.apiUrl)
		if err != nil {
			return nil, fmt.Errorf("Error getting user info: %s", err)
		}

		err = json.Unmarshal(response.Body, &data)
		if err != nil {
			return nil, fmt.Errorf("Error decoding user info JSON: %s", err)
		}
	}

	name := s.extractName(&data)

	email := s.extractEmail(&data)

	login := s.extractLogin(&data, email)

	teams, orgRoles, isGrafanaAdmin := s.extractOrgRoles(token)

	userInfo := &BasicUserInfo{
		Name:           name,
		Login:          login,
		Email:          email,
		OrgRoles:       orgRoles,
		IsGrafanaAdmin: isGrafanaAdmin,
		Teams:          teams,
	}

	return userInfo, nil
}

func (s *SocialOIDC) extractToken(data *OIDCUserInfoJson, token *oauth2.Token) bool {
	idToken := token.Extra("id_token")
	if idToken == nil {
		s.log.Debug("No id_token found", "token", token)
		return false
	}

	jwtRegexp := regexp.MustCompile("^([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)$")
	matched := jwtRegexp.FindStringSubmatch(idToken.(string))
	if matched == nil {
		s.log.Debug("id_token is not in JWT format", "id_token", idToken.(string))
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(matched[2])
	if err != nil {
		s.log.Error("Error base64 decoding id_token", "raw_payload", matched[2], "err", err)
		return false
	}

	err = json.Unmarshal(payload, data)
	if err != nil {
		s.log.Error("Error decoding id_token JSON", "payload", string(payload), "err", err)
		return false
	}

	email := s.extractEmail(data)
	if email == "" {
		s.log.Debug("No email found in id_token", "json", string(payload), "data", data)
		return false
	}

	s.log.Debug("Received id_token", "json", string(payload), "data", data)
	return true
}

func (s *SocialOIDC) extractEmail(data *OIDCUserInfoJson) string {
	if data.Email != "" {
		return data.Email
	}

	email, ok := data.X[s.emailAttributeName]
	if ok && len(email.(string)) != 0 {
		return email.(string)
	}

	return ""
}

func (s *SocialOIDC) extractLogin(data *OIDCUserInfoJson, email string) string {
	if data.PreferredUsername != "" {
		return data.PreferredUsername
	}

	login, ok := data.X[s.usernameAttributeName]
	if ok && len(login.(string)) != 0 {
		return login.(string)
	}

	return email
}

func (s *SocialOIDC) extractName(data *OIDCUserInfoJson) string {
	if data.Name != "" {
		return data.Name
	}

	if data.GivenName != "" {
		return data.GivenName
	}

	name, ok := data.X[s.displaynameAttributeName]
	if ok && len(name.(string)) != 0 {
		return name.(string)
	}

	return ""
}

func (s *SocialOIDC) extractOrgRoles(token *oauth2.Token) (teams map[int64][]int64, orgRoles map[int64]models.RoleType, isGrafanaAdmin *bool) {
	accessTokenScopes := strings.Split(token.Extra("scope").(string), " ")
	teams, orgRoles, isGrafanaAdmin = oidc.GetOrgRolesFromScopes(accessTokenScopes)
	return
}
