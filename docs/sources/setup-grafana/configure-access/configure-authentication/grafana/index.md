---
aliases:
  - ../../../auth/grafana/ # /docs/grafana/next/auth/grafana/
  - ../../configure-security/setup-grafana/configure-security/configure-authentication/grafana/ # /docs/grafana/next/setup-grafana/configure-security/setup-grafana/configure-security/configure-authentication/grafana/
  - ../../configure-security/configure-authentication/grafana/ # /docs/grafana/next/setup-grafana/configure-security/configure-authentication/grafana/
description: Learn how to configure basic authentication in Grafana
labels:
  products:
    - enterprise
    - oss
menuTitle: Basic auth
title: Configure basic authentication
weight: 200
---

# Configure basic authentication

Grafana provides a basic authentication system with password authentication enabled by default. This document details configuration options to manage and enhance basic authentication.

## Disable basic authentication

To disable basic authentication, use the following configuration:

```bash
[auth.basic]
enabled = false
```

## Password policy

Grafana requires new and updated passwords for basic auth users to have at least 12 characters. The `password_policy` configuration option is enabled by default and adds character requirements on top of the minimum length.

With the `password_policy` option enabled, new and updated passwords must meet the following criteria:

- At least 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

To keep only the 12 character minimum, disable the option:

```bash
[auth.basic]
password_policy = false
```

{{< admonition type="note" >}}
Existing passwords that do not comply with the new password policy will not be affected until the user updates their password.
{{< /admonition >}}

## Disable login form

To hide the Grafana login form, use the following configuration setting:

```bash
[auth]
disable_login_form = true
```

This can be helpful in setups where authentication is handled entirely through external mechanisms or single sign-on (SSO).
