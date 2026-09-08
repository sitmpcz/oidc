# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Nette framework extension library (`sitmpcz/oidc`) that integrates OpenID Connect authentication into Nette applications. It wraps the `facile-it/php-openid-client` library and provides a Nette-friendly interface for OIDC flows, primarily targeting Keycloak as the identity provider.

## Architecture

### Core Components

1. **OpenIDExtension** (`src/DI/OpenIDExtension.php`): Nette DI extension that registers the OpenID client service
   - Validates configuration using Nette Schema
   - Accepts: `issuerUrl`, `clientId`, `clientSecret`, `redirectUri` (all **required** — `clientSecret` because only confidential clients are supported, PKCE is not implemented; `redirectUri` because deriving it from the request path is never what you want), `postLogoutRedirectUri`, `backchannelLogoutUri`, `scopes`, `idTokenSignedResponseAlg`
   - Default scopes: `['openid', 'profile', 'email']`; default `idTokenSignedResponseAlg`: `RS256`
   - All URI parameters support relative paths (domain is added automatically)

2. **OpenIDClientService** (`src/Security/OpenIDClientService.php`): Main service handling OIDC flows
   - Builds OIDC client from `facile-it/php-openid-client` in the constructor (IssuerBuilder fetches OIDC discovery document at startup)
   - Manages authorization flow and token handling
   - Stores user info and tokens in Nette session under the `'oidc'` section
   - Public methods:
     - `getAuthorizationUrl()`: Builds authorization URL with explicit `scope`, and generates a `state` + `nonce` which it stores in the session
     - `handleCallback()`: Processes OIDC callback. Verifies `state` (fail-fast on raw params before any network call, then again on processed params) and requires a matching `nonce` claim in the ID token, regenerates the session ID, then stores `userInfo`/`refreshToken`/`idToken` in session. Throws `RuntimeException` on missing pending request, state mismatch, nonce mismatch, or missing ID token
     - `refreshToken()`: Refreshes via `AuthorizationService::refresh()` (which verifies the returned ID token, unlike `grant()`), then updates `refreshToken` and `idToken` in session. Keeps the existing refresh token when the provider's rotation response omits a new one. Returns `bool`
     - `getLogoutUrl(?string $idToken)`: Returns OIDC provider end-session URL; throws `RuntimeException` if provider has no `end_session_endpoint`
     - `logout()`: Clears local session (`userInfo`, `refreshToken`, `idToken`, `authState`, `authNonce`) and regenerates the session ID
     - `getIdToken()`: Returns the stored ID token from session
     - `verifyLogoutToken(string $logoutToken)`: Verifies the signature against the provider JWKS plus spec claims (`events`, no `nonce`, `sid` or `sub` present) and returns the verified claims. Touches no session state. This is the entry point for apps that locate sessions themselves
     - `handleBackchannelLogout(string $logoutToken)`: Calls `verifyLogoutToken()`, then clears the **current request's** session if `sid`/`sub` matches (`sid` takes precedence). Wraps all exceptions as `RuntimeException`
     - `decodeJwtPayload(string $jwt)`: static; parses a JWT payload **without verifying the signature**. Only for already-verified tokens or tokens from your own storage — never for client input

### Session Management

The `'oidc'` session section persists:
- `userInfo`: Complete user info array from the OIDC provider
- `refreshToken`: OAuth2 refresh token
- `idToken`: ID token (needed for `getLogoutUrl()` and backchannel logout matching)
- `authState` / `authNonce`: one-shot CSRF/replay values, written by `getAuthorizationUrl()` and consumed (removed) at the start of `handleCallback()`

### Security invariants

Do not remove these without a replacement — each closes a specific attack:

- `state` is generated per authorization request and compared with `hash_equals` in `handleCallback()`. Without it, an attacker can replay their own `code` to log a victim into the attacker's account.
- `nonce` is generated per request and its presence in the ID token is asserted explicitly. The upstream `NonceChecker` only runs when the claim exists (`Jose\Component\Checker\ClaimCheckerManager::check()` skips absent claims), so an ID token with no `nonce` would otherwise pass silently. Since PKCE is not implemented, `nonce` is the only defence against authorization code injection (RFC 9700 accepts it for confidential clients).
- `id_token_signed_response_alg` is set in `clientMetadataArray`, which makes the verifier register an `AlgorithmChecker`. Without it `expectedAlg` is `null`, no algorithm allow-list applies, and the verifier's algorithm manager includes `Algorithm\None` whose `verify()` returns `true` for an empty signature without checking the key type — forgeable against any IdP whose JWKS omits `alg` on a signing key. This also covers the backchannel logout token, which is verified with the same builder.
- `regenerateSessionId()` runs on login and logout to prevent session fixation.

### Not implemented / known gaps

- No PKCE. `clientSecret` is therefore required; a public client would be unsafe here.
- `buildAbsoluteUrl()` trusts `X-Forwarded-*` with no trusted-proxy allow-list.
- No `jti` replay cache for backchannel logout tokens.
- No caching of the discovery document or JWKS; `getJWKFromKid()` reloads the JWKS on an unknown `kid` before signature verification, so unauthenticated requests can trigger refetches.

### Logout Mechanisms

1. **Front-channel logout**: `$oidc->logout()` + `$oidc->getLogoutUrl($idToken)` — clears local session and redirects to provider
2. **Backchannel logout**: Provider sends POST with `logout_token` JWT to the configured `backchannelLogoutUri`
   - `handleBackchannelLogout()` validates the token per [OIDC Back-Channel Logout spec](https://openid.net/specs/openid-connect-backchannel-1_0.html)
   - Matches session by `sid` (session ID) or `sub` (subject/user ID)
   - Only clears the current session — does **not** search across all sessions (see Redis note below)

### Redis Sessions and Backchannel Logout

When using Redis for session storage (`contributte/redis`), backchannel logout requires a different approach because `handleBackchannelLogout()` only sees the current request's session, not all active sessions. The pattern from README:

1. `verifyLogoutToken($logoutToken)` — **first**, before touching any session. Take `sid`/`sub` from its return value
2. `SCAN` (never `KEYS`) over the session Redis DB, parse the stored `idToken` out of each session blob
3. Match on `sid` (falling back to `sub` only when the token carries no `sid`) and delete matching keys
4. Respond with an empty 200 — no deleted-session count

The PHP session data format for Redis is: `oidc|a:3:{...}`. Extract `idToken` with regex:
```
s:7:"idToken";s:\d+:"([^"]+)"
```
Then `OpenIDClientService::decodeJwtPayload()` to read its `sid`/`sub`.

The order in step 1 is the whole security of this endpoint: it is unauthenticated and public, so a hand-decoded `logout_token` means anyone can delete anyone's session. `KEYS *` in step 2 is a blocking Redis call, which turns the same endpoint into a DoS on every session.

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
    redirectUri: "/sign/callback"          # required
    postLogoutRedirectUri: "/"             # optional
    backchannelLogoutUri: "/sign/out-slo"  # optional, enables SSO back-channel logout
    scopes: [openid, profile, email]       # optional, these are defaults
    idTokenSignedResponseAlg: RS256        # optional, this is the default
```

For Keycloak: set **Backchannel Logout URL** in Client Settings to `https://your-domain.cz/sign/out-slo` and enable **Backchannel Logout Session Required**.

## Development

No test infrastructure is configured. Install dependencies with:

```bash
composer install
```
