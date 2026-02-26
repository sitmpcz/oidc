# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Nette framework extension library (`sitmpcz/oidc`) that integrates OpenID Connect authentication into Nette applications. It wraps the `facile-it/php-openid-client` library and provides a Nette-friendly interface for OIDC flows, primarily targeting Keycloak as the identity provider.

## Architecture

### Core Components

1. **OpenIDExtension** (`src/DI/OpenIDExtension.php`): Nette DI extension that registers the OpenID client service
   - Validates configuration using Nette Schema
   - Accepts: `issuerUrl`, `clientId`, `clientSecret` (nullable — supports public PKCE clients), `redirectUri`, `postLogoutRedirectUri`, `backchannelLogoutUri`, `scopes`
   - Default scopes: `['openid', 'profile', 'email']`
   - All URI parameters support relative paths (domain is added automatically)

2. **OpenIDClientService** (`src/Security/OpenIDClientService.php`): Main service handling OIDC flows
   - Builds OIDC client from `facile-it/php-openid-client` in the constructor (IssuerBuilder fetches OIDC discovery document at startup)
   - Manages authorization flow and token handling
   - Stores user info and tokens in Nette session under the `'oidc'` section
   - Public methods:
     - `getAuthorizationUrl()`: Builds authorization URL, manually overrides the `scope` parameter (parses/rebuilds the URL)
     - `handleCallback()`: Processes OIDC callback, validates tokens, stores `userInfo`/`refreshToken`/`idToken` in session; throws `RuntimeException('Unauthorized')` if no ID token
     - `refreshToken()`: Refreshes access tokens using the stored refresh token; returns `bool`
     - `getLogoutUrl(?string $idToken)`: Returns OIDC provider end-session URL; throws `RuntimeException` if provider has no `end_session_endpoint`
     - `logout()`: Clears local session (`userInfo`, `refreshToken`, `idToken`)
     - `getIdToken()`: Returns the stored ID token from session
     - `handleBackchannelLogout(string $logoutToken)`: Validates JWT logout token and clears session if `sid`/`sub` matches; wraps all exceptions as `RuntimeException`

### Session Management

The `'oidc'` session section persists:
- `userInfo`: Complete user info array from the OIDC provider
- `refreshToken`: OAuth2 refresh token
- `idToken`: ID token (needed for `getLogoutUrl()` and backchannel logout matching)

### Logout Mechanisms

1. **Front-channel logout**: `$oidc->logout()` + `$oidc->getLogoutUrl($idToken)` — clears local session and redirects to provider
2. **Backchannel logout**: Provider sends POST with `logout_token` JWT to the configured `backchannelLogoutUri`
   - `handleBackchannelLogout()` validates the token per [OIDC Back-Channel Logout spec](https://openid.net/specs/openid-connect-backchannel-1_0.html)
   - Matches session by `sid` (session ID) or `sub` (subject/user ID)
   - Only clears the current session — does **not** search across all sessions (see Redis note below)

### Redis Sessions and Backchannel Logout

When using Redis for session storage (`contributte/redis`), backchannel logout requires a different approach because `handleBackchannelLogout()` only sees the current request's session, not all active sessions. The pattern from README:

1. Decode the `logout_token` JWT manually (base64url decode payload)
2. Extract `sid`/`sub` claims
3. Iterate all Redis session keys, deserialize each, parse the stored `idToken` from the `oidc` section
4. Match `sid`/`sub` and delete matching sessions directly from Redis

The PHP session data format for Redis is: `oidc|a:3:{...}`. Extract `idToken` with regex:
```
s:7:"idToken";s:\d+:"([^"]+)"
```
Then base64url-decode the JWT payload to get `sid`/`sub` claims.

Use a dedicated Redis database for sessions (e.g., DB 1) separate from cache (DB 0).

### URL Construction (`buildAbsoluteUrl`)

The private `buildAbsoluteUrl()` method handles reverse proxy headers (`X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`). Important edge case: Kubernetes Ingress often sends `X-Forwarded-Port: 80` even for HTTPS traffic — the method normalizes this by using the standard port for the detected scheme instead.

### Integration Pattern

Typical Nette presenter integration:
1. `actionLogin()`: `$this->redirectUrl($this->oidc->getAuthorizationUrl())`
2. `actionCallback()`: `$userInfo = $this->oidc->handleCallback()`, then login user
3. `actionLogout()`: `$idToken = $this->oidc->getIdToken()`, then `$this->oidc->logout()`, then `$this->redirectUrl($this->oidc->getLogoutUrl($idToken))`
4. `actionOutSlo()`: Read `logout_token` POST param, call `$this->oidc->handleBackchannelLogout($token)`, respond HTTP 200

### Configuration

```neon
extensions:
    openid: Sitmpcz\oidc\DI\OpenIDExtension

openid:
    issuerUrl: %env.ISSUER_URL%
    clientId: %env.CLIENT_ID%
    clientSecret: %env.CLIENT_SECRET%
    redirectUri: "/sign/callback"          # optional, auto-generated from request if omitted
    postLogoutRedirectUri: "/"             # optional
    backchannelLogoutUri: "/sign/out-slo"  # optional, enables SSO back-channel logout
    scopes: [openid, profile, email]       # optional, these are defaults
```

For Keycloak: set **Backchannel Logout URL** in Client Settings to `https://your-domain.cz/sign/out-slo` and enable **Backchannel Logout Session Required**.

## Development

No test infrastructure is configured. Install dependencies with:

```bash
composer install
```
