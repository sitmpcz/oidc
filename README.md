# sitmpcz/oidc

OpenID Connect (OIDC) extension pro Nette Framework s podporou Keycloak a dalších OIDC providerů.

Knihovna integruje [`facile-it/php-openid-client`](https://github.com/facile-it/php-openid-client) do Nette aplikací a poskytuje jednoduché API pro autentizaci přes OpenID Connect, včetně podpory pro **backchannel logout** (Single Sign-Out).

## Požadavky

- PHP 8.1 nebo vyšší
- Nette Framework 3.1+
- OpenID Connect provider (např. Keycloak)

## Instalace

```bash
composer require sitmpcz/oidc
```

## Konfigurace

Zaregistrujte extension v `config.neon`:

```neon
extensions:
    openid: Sitmpcz\oidc\DI\OpenIDExtension

openid:
    issuerUrl: %env.ISSUER_URL%              # URL OIDC providera
    clientId: %env.CLIENT_ID%                # Client ID z OIDC providera
    clientSecret: %env.CLIENT_SECRET%        # Client Secret z OIDC providera
    redirectUri: "/sign/callback"            # volitelné
    postLogoutRedirectUri: "/"               # volitelné
    backchannelLogoutUri: "/sign/out-slo"    # volitelné
    scopes: [openid, profile, email]         # volitelné
```

### Parametry konfigurace

| Parametr | Povinný | Popis |
|----------|---------|-------|
| `issuerUrl` | Ano | URL vašeho OIDC providera (např. `https://keycloak.example.com/realms/myrealm`) |
| `clientId` | Ano | Client ID z konfigurace OIDC providera |
| `clientSecret` | Ano | Client Secret z konfigurace OIDC providera |
| `redirectUri` | Ne | URI pro callback po přihlášení. Pokud neuvedete, použije se aktuální URL z requestu |
| `postLogoutRedirectUri` | Ne | URI pro přesměrování po odhlášení. Výchozí: `/` |
| `backchannelLogoutUri` | Ne | URI endpoint pro backchannel logout (Single Sign-Out) |
| `scopes` | Ne | OIDC scopes. Výchozí: `[openid, profile, email]` |

**Relativní vs. Absolutní URL:**
Všechny URI parametry podporují relativní cesty (např. `/sign/callback`). Knihovna automaticky doplní schéma, doménu a port z aktuálního HTTP requestu. Můžete také používat absolutní URL.

### Podpora Reverse Proxy

Pokud běžíte za reverse proxy (nginx, Apache) nebo v Kubernetes Ingress, knihovna automaticky detekuje:
- `X-Forwarded-Proto` - pro detekci HTTPS
- `X-Forwarded-Host` - pro správný hostname
- `X-Forwarded-Port` - pro správný port

Ujistěte se, že vaše proxy tyto hlavičky správně nastavuje.

**Příklad pro nginx:**
```nginx
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;
```

**Příklad pro Kubernetes Ingress:**
Většina Ingress controllers (nginx-ingress, Traefik) nastavuje tyto hlavičky automaticky.

## Použití v presenteru

```php
<?php

declare(strict_types=1);

namespace App\Presenters;

use Nette\Application\UI\Presenter;
use Sitmpcz\oidc\Security\OpenIDClientService;

final class SignPresenter extends Presenter
{
    public function __construct(
        private OpenIDClientService $oidc
    ) {}

    public function actionLogin(): void
    {
        $this->redirectUrl($this->oidc->getAuthorizationUrl());
    }

    public function actionCallback(): void
    {
        $userinfo = $this->oidc->handleCallback();
        
        // Použijte eventuelně vlastní Authenticator pro přiřazení rolí a oprávnění
        $this->getUser()->login($userinfo['preferred_username']);
        $this->redirect('Homepage:');
    }

    public function actionLogout(): void
    {
        // Získat ID token před odhlášením (nutný pro id_token_hint v OIDC logout URL)
        $idToken = $this->oidc->getIdToken();

        // Vyčistit lokální session
        $this->oidc->logout();
        $this->getUser()->logout();

        // Přesměrovat na OIDC provider pro globální odhlášení
        $this->redirectUrl($this->oidc->getLogoutUrl($idToken));
    }

    /**
     * Endpoint pro backchannel logout - volá ho Keycloak při odhlášení z jiné aplikace
     * URL: /sign/out-slo
     */
    public function actionOutSlo(): void
    {
        $logoutToken = $this->getHttpRequest()->getPost('logout_token');

        if (!$logoutToken) {
            $this->error('Missing logout_token', 400);
        }

        try {
            $success = $this->oidc->handleBackchannelLogout($logoutToken);

            if ($success) {
                $this->getUser()->logout(true);
            }

            // OIDC specifikace vyžaduje HTTP 200 bez obsahu
            $this->sendResponse(new \Nette\Application\Responses\TextResponse(''));
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage(), 400);
        }
    }
}
```

### Použití s Redis sessions (contributte/redis)

Pokud používáte Redis pro ukládání sessions, backchannel logout vyžaduje speciální přístup, protože Keycloak nemá přímý přístup k vaší aktivní session - musíte vyhledat session v Redis podle `sid` (session ID) z logout tokenu.

#### Konfigurace Redis

**config/redis.neon:**
```neon
extensions:
    redis: Contributte\Redis\DI\RedisExtension

redis:
    debug: %debugMode%
    connection:
        default:
            uri: tcp://redis:6379
            sessions: false
            storage: true
            options: ['parameters': ['database': 0]]
        session:
            uri: tcp://redis:6379
            sessions: true  # Redis jako session handler
            storage: false
            options: ['parameters': ['database': 1]]  # Oddělená databáze pro sessions
```

**config/common.neon:**
```neon
extensions:
    openid: Sitmpcz\oidc\DI\OpenIDExtension

openid:
    issuerUrl: %env.ISSUER_URL%
    clientId: %env.CLIENT_ID%
    clientSecret: %env.CLIENT_SECRET%
    redirectUri: "/sign/callback"
    postLogoutRedirectUri: "/sign/in"
    backchannelLogoutUri: "/sign/out-slo"
    scopes: [openid, profile, email]

services:
    # SignPresenter s explicitním Redis klientem pro backchannel logout
    - App\Presenters\SignPresenter(
        redisSession: @redis.connection.session.client
    )
```

#### Presenter s Redis backchannel logout

```php
<?php

declare(strict_types=1);

namespace App\Presenters;

use Nette\Application\UI\Presenter;
use Sitmpcz\oidc\Security\OpenIDClientService;
use Predis\ClientInterface as RedisClient;

final class SignPresenter extends Presenter
{
    public function __construct(
        private OpenIDClientService $oidc,
        private RedisClient $redisSession  // Redis klient pro sessions (databáze 1)
    ) {}

    public function actionLogin(): void
    {
        $this->redirectUrl($this->oidc->getAuthorizationUrl());
    }

    public function actionCallback(): void
    {
        $userinfo = $this->oidc->handleCallback();
        $this->getUser()->login($userinfo['preferred_username']);
        $this->redirect('Homepage:');
    }

    public function actionOut(): void
    {
        $idToken = $this->oidc->getIdToken();

        // Odhlásit lokálně
        $this->getUser()->logout();
        $this->oidc->logout();

        // Zničit celou session včetně dat v Redis
        $this->session->destroy();

        // Přesměrovat na OIDC logout endpoint (Single Sign-Out)
        $this->redirectUrl($this->oidc->getLogoutUrl($idToken));
    }

    /**
     * Backchannel logout endpoint - vyhledává sessions v Redis podle sid/sub
     * URL: /sign/out-slo
     */
    #[Requires(methods: 'POST')]
    public function actionOutSlo(): void
    {
        $logoutToken = $this->getHttpRequest()->getPost('logout_token');

        if (!$logoutToken) {
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendJson(['error' => 'logout_token parameter is required']);
        }

        // Validate JWT logout token signature per OIDC spec
        try {
            $this->oidc->handleBackchannelLogout($logoutToken);
        } catch (\Throwable $e) {
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendJson(['error' => $e->getMessage()]);
        }

        // Decode JWT claims (signature already verified above)
        $parts = explode('.', $logoutToken);
        $b64 = strtr($parts[1], '-_', '+/');
        $b64 = str_pad($b64, strlen($b64) + (4 - strlen($b64) % 4) % 4, '=');
        $payload = json_decode(base64_decode($b64), true);
        $sid = $payload['sid'] ?? null;
        $sub = $payload['sub'] ?? null;

        // Scan all session keys in Redis using SCAN (non-blocking, unlike KEYS)
        $cursor = '0';
        do {
            [$cursor, $keys] = $this->redisSession->scan($cursor, ['COUNT' => 100]);
            foreach ($keys as $sessionKey) {
                $sessionData = $this->redisSession->get($sessionKey);
                if (!$sessionData || !str_contains($sessionData, 'oidc')) {
                    continue;
                }

                // Extract idToken from serialized session data
                // Format: oidc|a:3:{s:8:"userInfo";a:...;s:7:"idToken";s:NNN:"...";
                if (!preg_match('/s:7:"idToken";s:\d+:"([^"]+)"/', $sessionData, $matches)) {
                    continue;
                }

                $idParts = explode('.', $matches[1]);
                if (count($idParts) !== 3) {
                    continue;
                }

                $idB64 = strtr($idParts[1], '-_', '+/');
                $idB64 = str_pad($idB64, strlen($idB64) + (4 - strlen($idB64) % 4) % 4, '=');
                $idPayload = json_decode(base64_decode($idB64), true);
                if (!is_array($idPayload)) {
                    continue;
                }

                if (($sid && ($idPayload['sid'] ?? null) === $sid) || ($sub && ($idPayload['sub'] ?? null) === $sub)) {
                    $this->redisSession->del($sessionKey);
                }
            }
        } while ($cursor !== '0');

        $this->sendResponse(new TextResponse(''));
    }
}
```

#### Důležité poznámky pro Redis

1. **Oddělené databáze**: Používejte samostatnou Redis databázi pro sessions (např. databáze 1) oddělenou od cache (databáze 0)

2. **Backchannel logout vyžaduje vyhledávání**: Na rozdíl od standardních Nette sessions, kde je aktivní session dostupná v kontextu requestu, u backchannel logout musíte:
   - Projít všechny session klíče v Redis
   - Deserializovat session data
   - Najít ID token v sekci `oidc`
   - Porovnat `sid` nebo `sub` z logout tokenu s ID tokenem v session
   - Smazat odpovídající session z Redis

3. **Výkon**: Pro velký počet aktivních sessions může být vyhledávání pomalé. Zvažte:
   - Index sessions podle `sid` v samostatné Redis struktuře
   - TTL pro Redis session klíče odpovídající session expiraci
   - Monitoring počtu aktivních sessions

4. **Bezpečnost**: Backchannel endpoint neověřuje JWT logout token - v produkčním prostředí zvažte přidání validace tokenu pomocí `OpenIDClientService::handleBackchannelLogout()` před vyhledáváním v Redis.

## Dostupné metody

### `getAuthorizationUrl(): string`
Vrací URL pro přesměrování na přihlašovací stránku OIDC providera.

### `handleCallback(): array`
Zpracuje callback z OIDC providera a vrátí informace o uživateli.

### `refreshToken(): bool`
Obnoví access token pomocí refresh tokenu. Vrací `true` při úspěchu, `false` při selhání.

### `getLogoutUrl(?string $idToken = null): string`
Vrací URL pro odhlášení z OIDC providera. Při zadání ID tokenu poskytuje lepší single sign-out.

### `logout(): void`
Vyčistí lokální session (userInfo, refreshToken, idToken).

### `getIdToken(): ?string`
Vrací uložený ID token ze session, pokud existuje.

### `handleBackchannelLogout(string $logoutToken): bool`
Zpracuje backchannel logout požadavek z OIDC providera (např. Keycloak). Validuje JWT logout token a odhlásí lokální session, pokud token odpovídá aktuálnímu uživateli. Vrací `true` pokud byla session odhlášena.

## Backchannel Logout (Single Sign-Out)

Backchannel logout umožňuje OIDC provideru automaticky odhlásit uživatele z vaší aplikace, když se odhlásí z jiné aplikace připojené ke stejnému provideru.

### Konfigurace v Keycloak

1. V Keycloak administraci přejděte na **Client Settings** vašeho klienta
2. Nastavte **Backchannel Logout URL**: `https://vase-domena.cz/sign/out-slo`
3. Zapněte **Backchannel Logout Session Required**

**Tip:** V `config.neon` stačí uvést relativní cestu (`backchannelLogoutUri: "/sign/out-slo"`), knihovna automaticky sestaví plnou URL.

### Jak to funguje

1. Uživatel se odhlásí z aplikace A připojené ke Keycloak
2. Keycloak pošle POST požadavek na backchannel logout endpoint aplikace B
3. Aplikace B validuje JWT `logout_token` a odhlásí uživatele
4. Uživatel je nyní odhlášen ze všech aplikací (Single Sign-Out)

Token je validován podle [OIDC Back-Channel Logout specifikace](https://openid.net/specs/openid-connect-backchannel-1_0.html) a session je spárována podle `sid` (session ID) nebo `sub` (subject/user ID).

## Klíčové vlastnosti

- Automatické sestavování absolutních URL z relativních cest
- Podpora reverse proxy a Kubernetes Ingress
- Front-channel a backchannel logout
- Správa session v Nette session storage
- Automatická obnova tokenů přes refresh token
- JWT validace podle OIDC standardů

## Licence

MIT
