package social

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/util/errutil"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/oidc"

	"github.com/jmespath/go-jmespath"
	"golang.org/x/oauth2"
)

type SocialOIDC struct {
	*SocialBase
	allowedDomains           []string
	apiUrl                   string
	allowSignup              bool
	emailAttributeName       string
	emailAttributePath       string
	usernameAttributeName    string
	usernameAttributePath    string
	displaynameAttributeName string
	displaynameAttributePath string
	roleAttributePath        string
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
	rawJSON           []byte
}

func (info *OIDCUserInfoJson) String() string {
	return fmt.Sprintf(
		"Name: %s, GivenName: %s, PrefferedUsername: %s, Email: %s",
		info.Name, info.GivenName, info.PreferredUsername, info.Email)
}

func (s *SocialOIDC) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data OIDCUserInfoJson

	userInfo := &BasicUserInfo{}

	if s.extractToken(&data, token) {
		s.fillUserInfo(userInfo, &data)
	}

	if s.extractAPI(&data, client) {
		s.fillUserInfo(userInfo, &data)
	}

	if userInfo.Login == "" {
		userInfo.Login = userInfo.Email
	}

	if len(userInfo.OrgRoles) == 0 {
		userInfo.Teams, userInfo.OrgRoles, userInfo.IsGrafanaAdmin = s.extractOrgRoles(token)
	}

	s.log.Debug("User info result", "result", userInfo)
	return userInfo, nil
}

func (s *SocialOIDC) fillUserInfo(userInfo *BasicUserInfo, data *OIDCUserInfoJson) {
	if userInfo.Email == "" {
		userInfo.Email = s.extractEmail(data)
	}
	if userInfo.Name == "" {
		userInfo.Name = s.extractName(data)
	}
	if userInfo.Login == "" {
		userInfo.Login = s.extractLogin(data)
	}
}

func (s *SocialOIDC) extractToken(data *OIDCUserInfoJson, token *oauth2.Token) bool {
	var err error

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

	data.rawJSON, err = base64.RawURLEncoding.DecodeString(matched[2])
	if err != nil {
		s.log.Error("Error base64 decoding id_token", "raw_payload", matched[2], "error", err)
		return false
	}

	err = json.Unmarshal(data.rawJSON, data)
	if err != nil {
		s.log.Error("Error decoding id_token JSON", "raw_json", string(data.rawJSON), "error", err)
		data.rawJSON = []byte{}
		return false
	}

	s.log.Debug("Received id_token", "raw_json", string(data.rawJSON), "data", data)
	return true
}

func (s *SocialOIDC) extractAPI(data *OIDCUserInfoJson, client *http.Client) bool {
	rawUserInfoResponse, err := HttpGet(client, s.apiUrl)
	if err != nil {
		s.log.Debug("Error getting user info response", "url", s.apiUrl, "error", err)
		return false
	}
	data.rawJSON = rawUserInfoResponse.Body

	err = json.Unmarshal(data.rawJSON, data)
	if err != nil {
		s.log.Error("Error decoding user info response", "raw_json", data.rawJSON, "error", err)
		data.rawJSON = []byte{}
		return false
	}

	s.log.Debug("Received user info response", "raw_json", string(data.rawJSON), "data", data)
	return true
}

func (s *SocialOIDC) extractEmail(data *OIDCUserInfoJson) string {
	if data.Email != "" {
		return data.Email
	}

	if s.emailAttributePath != "" {
		email := s.searchJSONForAttr(s.emailAttributePath, data.rawJSON)
		if email != "" {
			return email
		}
	}

	email, ok := data.X[s.emailAttributeName]
	if ok && len(email.(string)) != 0 {
		return email.(string)
	}

	return ""
}

func (s *SocialOIDC) extractLogin(data *OIDCUserInfoJson) string {
	if data.PreferredUsername != "" {
		return data.PreferredUsername
	}

	if s.usernameAttributePath != "" {
		username := s.searchJSONForAttr(s.usernameAttributePath, data.rawJSON)
		if username != "" {
			return username
		}
	}

	username, ok := data.X[s.usernameAttributeName]
	if ok && len(username.(string)) != 0 {
		return username.(string)
	}

	return ""
}

func (s *SocialOIDC) extractName(data *OIDCUserInfoJson) string {
	if data.Name != "" {
		return data.Name
	}

	if data.GivenName != "" {
		return data.GivenName
	}

	if s.displaynameAttributePath != "" {
		name := s.searchJSONForAttr(s.displaynameAttributePath, data.rawJSON)
		if name != "" {
			return name
		}
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

// searchJSONForAttr searches the provided JSON response for the given attribute
// using the configured  attribute path associated with the generic OAuth
// provider.
// Returns an empty string if an attribute is not found.
func (s *SocialOIDC) searchJSONForAttr(attributePath string, data []byte) string {
	if attributePath == "" {
		s.log.Error("No attribute path specified")
		return ""
	}
	if len(data) == 0 {
		s.log.Error("Empty user info JSON response provided")
		return ""
	}
	var buf interface{}
	if err := json.Unmarshal(data, &buf); err != nil {
		s.log.Error("Failed to unmarshal user info JSON response", "err", err.Error())
		return ""
	}
	val, err := jmespath.Search(attributePath, buf)
	if err != nil {
		s.log.Error("Failed to search user info JSON response with provided path", "attributePath", attributePath, "err", err.Error())
		return ""
	}
	strVal, ok := val.(string)
	if ok {
		return strVal
	}
	s.log.Error("Attribute not found when searching JSON with provided path", "attributePath", attributePath)
	return ""
}

func (s *SocialOIDC) FetchPrivateEmail(client *http.Client) (string, error) {
	type Record struct {
		Email       string `json:"email"`
		Primary     bool   `json:"primary"`
		IsPrimary   bool   `json:"is_primary"`
		Verified    bool   `json:"verified"`
		IsConfirmed bool   `json:"is_confirmed"`
	}

	response, err := HttpGet(client, fmt.Sprintf(s.apiUrl+"/emails"))
	if err != nil {
		s.log.Error("Error getting email address", "url", s.apiUrl+"/emails", "error", err)
		return "", errutil.Wrap("Error getting email address", err)
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		var data struct {
			Values []Record `json:"values"`
		}

		err = json.Unmarshal(response.Body, &data)
		if err != nil {
			s.log.Error("Error decoding email addresses response", "raw_json", string(response.Body), "error", err)
			return "", errutil.Wrap("Erro decoding email addresses response", err)
		}

		records = data.Values
	}

	s.log.Debug("Received email addresses", "emails", records)

	var email = ""
	for _, record := range records {
		if record.Primary || record.IsPrimary {
			email = record.Email
			break
		}
	}

	s.log.Debug("Using email address", "email", email)

	return email, nil
}

func (s *SocialOIDC) FetchTeamMemberships(client *http.Client) ([]int, bool) {
	type Record struct {
		Id int `json:"id"`
	}

	response, err := HttpGet(client, fmt.Sprintf(s.apiUrl+"/teams"))
	if err != nil {
		s.log.Error("Error getting team memberships", "url", s.apiUrl+"/teams", "error", err)
		return nil, false
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		s.log.Error("Error decoding team memberships response", "raw_json", string(response.Body), "error", err)
		return nil, false
	}

	var ids = make([]int, len(records))
	for i, record := range records {
		ids[i] = record.Id
	}

	s.log.Debug("Received team memberships", "ids", ids)

	return ids, true
}

func (s *SocialOIDC) FetchOrganizations(client *http.Client) ([]string, bool) {
	type Record struct {
		Login string `json:"login"`
	}

	response, err := HttpGet(client, fmt.Sprintf(s.apiUrl+"/orgs"))
	if err != nil {
		s.log.Error("Error getting organizations", "url", s.apiUrl+"/orgs", "error", err)
		return nil, false
	}

	var records []Record

	err = json.Unmarshal(response.Body, &records)
	if err != nil {
		s.log.Error("Error decoding organization response", "response", string(response.Body), "error", err)
		return nil, false
	}

	var logins = make([]string, len(records))
	for i, record := range records {
		logins[i] = record.Login
	}

	s.log.Debug("Received organizations", "logins", logins)

	return logins, true
}
