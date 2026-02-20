# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Nette framework extension library (`sitmpcz/oidc`) that integrates OpenID Connect authentication into Nette applications. It wraps the `facile-it/php-openid-client` library and provides a Nette-friendly interface for OIDC flows, primarily targeting Keycloak as the identity provider.

## Architecture

### Core Components

The library consists of two main components:

1. **OpenIDExtension** (`src/DI/OpenIDExtension.php`): Nette DI extension that registers the OpenID client service
   - Validates configuration using Nette Schema
   - Accepts: `issuerUrl`, `clientId`, `clientSecret`, `redirectUri` (optional), `postLogoutRedirectUri`, `backchannelLogoutUri`, `scopes`
   - Default scopes: `['openid', 'profile', 'email']`
   - All URI parameters support relative paths (domain is added automatically)

2. **OpenIDClientService** (`src/Security/OpenIDClientService.php`): Main service handling OIDC flows
   - Builds OIDC client from `facile-it/php-openid-client`
   - Manages authorization flow and token handling
   - Stores user info and refresh tokens in Nette session under 'oidc' section
   - Key methods:
     - `getAuthorizationUrl()`: Returns the authorization redirect URL
     - `handleCallback()`: Processes OIDC callback, validates tokens, retrieves user info
     - `refreshToken()`: Refreshes access tokens using stored refresh token

### Session Management

The service uses Nette's session to persist:
- `userInfo`: Complete user information from the OIDC provider
- `refreshToken`: OAuth2 refresh token for token renewal
- `idToken`: ID token for logout operations

### Logout Mechanisms

The service supports two types of logout:

1. **Front-channel logout**: User-initiated logout via `getLogoutUrl()` and `logout()`
2. **Backchannel logout**: Provider-initiated logout when user logs out from another application
   - Endpoint receives POST with `logout_token` JWT
   - Token is validated according to OIDC Back-Channel Logout spec
   - Session is matched by `sid` (session ID) or `sub` (subject/user ID)
   - Implements automatic single sign-out across all connected applications

### Integration Pattern

Typical Nette presenter integration:
1. Login action: Redirect to `$oidc->getAuthorizationUrl()`
2. Callback action: Call `$oidc->handleCallback()` to get user info, then login user
3. The callback URL must match the `redirectUri` configured in config.neon

### Configuration

Extension registration in `config.neon`:
```neon
extensions:
    openid: Sitmpcz\oidc\DI\OpenIDExtension

openid:
    issuerUrl: %env.ISSUER_URL%
    clientId: %env.CLIENT_ID%
    clientSecret: %env.CLIENT_SECRET%
    redirectUri: "/sign/callback"  # optional, auto-generated from request if not provided
    postLogoutRedirectUri: "/"  # optional, relative path (domain added automatically)
    backchannelLogoutUri: "/sign/out-slo"  # optional, for SSO, relative path
    scopes: [openid, profile, email]  # optional, these are defaults
```

**Note**: All URI parameters now support relative paths. The service automatically converts them to absolute URLs using the current HTTP request's scheme, host, and port. You can still provide absolute URLs if needed.

**Reverse Proxy Support**: When running behind a reverse proxy, the service automatically detects and uses `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Port` headers to build correct absolute URLs (e.g., HTTPS URLs when SSL is terminated at the proxy).

## Development Commands

This is a library package with no build or test infrastructure currently configured.

### Composer

```bash
# Install dependencies
composer install

# Update dependencies
composer update
```

## Dependencies

Key libraries:
- `nette/di` ^3.1: Dependency injection container
- `nette/http` ^3.1: HTTP request/response and session management
- `facile-it/php-openid-client` ^0.3.5: Core OIDC client implementation
- `web-token/jwt-framework` ^3.4: JWT token validation
- `contributte/psr7-http-message` ^0.10.0: PSR-7 bridge for Nette HTTP objects

## Notes

- Minimum PHP version: 8.1
- The service constructs the authorization URL immediately in the constructor
- Callback processing expects standard OAuth2/OIDC query parameters from the identity provider
- Token refresh is handled separately via the `refreshToken()` method (not automatic)
