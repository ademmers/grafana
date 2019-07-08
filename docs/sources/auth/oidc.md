+++
title = "OpenID Connect authentication and authorization"
description = "Grafana OpenID Connect Guide "
keywords = ["grafana", "configuration", "documentation", "oidc"]
type = "docs"
[menu.docs]
name = "OpenID Connect"
identifier = "oidc"
parent = "authentication"
weight = 3
+++

# OpenID Connect Authentication

You can configure many different oidc authentication services with Grafana using the generic oidc feature.

This callback URL must match the full HTTP address that you use in your browser to access Grafana, but with the prefix path of `/login/oidc`.

You may have to set the `root_url` option of `[server]` for the callback URL to be
correct. For example in case you are serving Grafana behind a proxy.

Example config:

```bash
[auth.oidc]
enabled = true
client_id = YOUR_APP_CLIENT_ID
client_secret = YOUR_APP_CLIENT_SECRET
scopes = openid email profile
auth_url =
token_url =
api_url =
allowed_domains = mycompany.com mycompany.org
allow_sign_up = true
```

Set `api_url` to the resource that returns [OpenID UserInfo](https://connect2id.com/products/server/docs/api/userinfo) compatible information.

<hr>
