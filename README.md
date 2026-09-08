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
    redirectUri: "/sign/callback"            # povinné
    postLogoutRedirectUri: "/"               # volitelné
    backchannelLogoutUri: "/sign/out-slo"    # volitelné
    scopes: [openid, profile, email]         # volitelné
    idTokenSignedResponseAlg: RS256          # volitelné, výchozí RS256
```

### Parametry konfigurace

| Parametr | Povinný | Popis |
|----------|---------|-------|
| `issuerUrl` | Ano | URL vašeho OIDC providera (např. `https://keycloak.example.com/realms/myrealm`) |
| `clientId` | Ano | Client ID z konfigurace OIDC providera |
| `clientSecret` | Ano | Client Secret z konfigurace OIDC providera. Knihovna podporuje pouze confidential klienty — pro public klienta by bylo potřeba PKCE, které implementované není |
| `redirectUri` | Ano | URI pro callback po přihlášení. Musí odpovídat *Valid redirect URIs* u klienta v Keycloaku |
| `postLogoutRedirectUri` | Ne | URI pro přesměrování po odhlášení. Výchozí: `/` |
| `backchannelLogoutUri` | Ne | URI endpoint pro backchannel logout (Single Sign-Out) |
| `scopes` | Ne | OIDC scopes. Výchozí: `[openid, profile, email]` |
| `idTokenSignedResponseAlg` | Ne | Očekávaný podpisový algoritmus ID tokenu. Výchozí: `RS256`. Měňte jen když provider podepisuje jinak (Keycloak výchozí RS256) |

**Relativní vs. Absolutní URL:**
Všechny URI parametry podporují relativní cesty (např. `/sign/callback`). Knihovna automaticky doplní schéma, doménu a port z aktuálního HTTP requestu. Můžete také používat absolutní URL.

### Podpora Reverse Proxy

Pokud běžíte za reverse proxy (nginx, Apache) nebo v Kubernetes Ingress, knihovna automaticky detekuje:
- `X-Forwarded-Proto` - pro detekci HTTPS
- `X-Forwarded-Host` - pro správný hostname
- `X-Forwarded-Port` - pro správný port

Ujistěte se, že vaše proxy tyto hlavičky správně nastavuje.

> **Pozor:** knihovna těmto hlavičkám věří bez ověření, že request skutečně přišel od tvé proxy. Kdokoli je může poslat a ovlivnit tím sestavené `redirect_uri`. Nastav trusted proxy (`Nette\Http\RequestFactory::setProxy()`), nebo zadej URI parametry jako absolutní URL — pak se hlavičky nepoužijí vůbec. Viz [Zabezpečení](#zabezpečení).

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

use Nette\Application\Attributes\Requires;
use Nette\Application\Responses\TextResponse;
use Nette\Application\UI\Presenter;
use Sitmpcz\oidc\Security\OpenIDClientService;
use Tracy\Debugger;

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
        try {
            $userinfo = $this->oidc->handleCallback();
        } catch (\RuntimeException $e) {
            // Vypršelá session, nesouhlasící state, login otevřený ve dvou tabech.
            // Nepřesměrovávej zpět na actionLogin - hned by spustil nový OIDC flow
            // a při trvale nepřenesené cookie by vznikla redirect smyčka.
            Debugger::log($e, 'oidc');
            $this->flashMessage('Přihlášení vypršelo, zkuste to prosím znovu.', 'danger');
            $this->redirect('Homepage:');
        }

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
     *
     * POZOR: handleBackchannelLogout() vidí jen session aktuálního requestu.
     * Keycloak volá tenhle endpoint server-to-server bez session cookie, takže
     * ve většině nasazení nebude co spárovat. Tahle varianta je použitelná jen
     * tam, kde si session dohledáš sám - viz sekce o Redis sessions níže.
     */
    #[Requires(methods: 'POST')]
    public function actionOutSlo(): void
    {
        $logoutToken = $this->getHttpRequest()->getPost('logout_token');

        if (!is_string($logoutToken) || $logoutToken === '') {
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendResponse(new TextResponse(''));
        }

        try {
            $success = $this->oidc->handleBackchannelLogout($logoutToken);

            if ($success) {
                $this->getUser()->logout(true);
            }
        } catch (\RuntimeException $e) {
            // Detaily verifikace tokenu nikdy neposílej volajícímu - jen zaloguj
            Debugger::log($e, 'oidc');
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendResponse(new TextResponse(''));
        }

        // OIDC specifikace vyžaduje HTTP 200 bez obsahu
        $this->sendResponse(new TextResponse(''));
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

use Nette\Application\Attributes\Requires;
use Nette\Application\Responses\TextResponse;
use Nette\Application\UI\Presenter;
use Sitmpcz\oidc\Security\OpenIDClientService;
use Predis\ClientInterface as RedisClient;
use Tracy\Debugger;

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
        try {
            $userinfo = $this->oidc->handleCallback();
        } catch (\RuntimeException $e) {
            Debugger::log($e, 'oidc');
            $this->flashMessage('Přihlášení vypršelo, zkuste to prosím znovu.', 'danger');
            $this->redirect('Homepage:');
        }

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

        if (!is_string($logoutToken) || $logoutToken === '') {
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendResponse(new TextResponse(''));
        }

        // KLÍČOVÉ: ověř podpis a claims tokenu PŘED jakoukoli manipulací se session.
        // Bez toho je endpoint neautentizovaná mazačka session pro kohokoli.
        try {
            $claims = $this->oidc->verifyLogoutToken($logoutToken);
        } catch (\RuntimeException $e) {
            // Nevracej $e->getMessage() - leakuje detaily verifikace tokenu
            Debugger::log($e, 'oidc');
            $this->getHttpResponse()->setCode(\Nette\Http\Response::S400_BadRequest);
            $this->sendResponse(new TextResponse(''));
        }

        $sid = $claims['sid'] ?? null;
        $sub = $claims['sub'] ?? null;

        // Scan all session keys in Redis using SCAN (non-blocking, unlike KEYS)
        $cursor = '0';
        do {
            [$cursor, $keys] = $this->redisSession->scan($cursor, ['COUNT' => 100]);
            foreach ($keys as $sessionKey) {
                $sessionData = $this->redisSession->get($sessionKey);
                if (!$sessionData) {
                    continue;
                }

                // Extract idToken from serialized session data
                // Format: oidc|a:3:{s:8:"userInfo";a:...;s:7:"idToken";s:NNN:"...";
                if (!preg_match('/s:7:"idToken";s:\d+:"([^"]+)"/', $sessionData, $matches)) {
                    continue;
                }

                // Token z vlastního storage, podpis už ověřený při přihlášení
                $idPayload = OpenIDClientService::decodeJwtPayload($matches[1]);
                if ($idPayload === null) {
                    continue;
                }

                // sid má přednost; sub se použije jen když sid v logout tokenu není
                $match = $sid !== null
                    ? ($idPayload['sid'] ?? null) === $sid
                    : ($sub !== null && ($idPayload['sub'] ?? null) === $sub);

                if ($match) {
                    $this->redisSession->del($sessionKey);
                }
            }
        } while ($cursor !== '0');

        // Spec vyžaduje prázdnou 200 - počet smazaných session neposílej,
        // byl by to oracle na to, kdo je právě přihlášený
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

4. **Bezpečnost — nejdůležitější bod celé sekce**: `verifyLogoutToken()` musí být zavoláno **před** vyhledáváním v Redis a `sid`/`sub` se musí brát z jeho návratové hodnoty, ne z ručně dekódovaného JWT. Endpoint je veřejný a neautentizovaný; bez ověření podpisu maže session komukoli, kdo pošle vlastní nepodepsaný token.

5. **Nikdy nepoužívej `KEYS *`** — blokuje celý Redis po dobu průchodu keyspace, takže neautentizovaný POST na tenhle endpoint se stává DoS na všechny session. Vždy `SCAN`, jako v příkladu.

6. **Neposílej v odpovědi počet smazaných session** — útočník by iterováním `sub` zjistil, kdo je právě přihlášený. Spec chce prázdnou 200.

## Dostupné metody

### `getAuthorizationUrl(): string`
Vrací URL pro přesměrování na přihlašovací stránku OIDC providera. Vygeneruje `state` a `nonce`, uloží je do session a přidá do URL. Musí být zavoláno ve stejné session, ve které pak proběhne `handleCallback()`.

### `handleCallback(): array`
Zpracuje callback z OIDC providera a vrátí informace o uživateli. Před vydáním dat ověří `state` a `nonce` a vygeneruje nové session ID. Hodí `RuntimeException`, pokud v session není čekající authorization request, pokud `state` nesouhlasí nebo pokud `nonce` v ID tokenu neodpovídá — na callback tedy nelze přijít „zvenčí", flow musí vždy začít voláním `getAuthorizationUrl()`.

### `refreshToken(): bool`
Obnoví tokeny pomocí uloženého refresh tokenu a aktualizuje v session `refreshToken` a `idToken`. Vrací `true` při úspěchu, `false` když v session žádný refresh token není nebo ho provider odmítl. Když provider při rotaci nový refresh token nevrátí, ponechá se ten stávající.

### `getLogoutUrl(?string $idToken = null): string`
Vrací end-session URL OIDC providera. Při zadání ID tokenu ho přidá jako `id_token_hint`, což provideru umožní odhlásit konkrétní session bez dotazu uživateli. Hodí `RuntimeException`, pokud provider `end_session_endpoint` v discovery dokumentu nemá.

### `logout(): void`
Vyčistí lokální session (userInfo, refreshToken, idToken, rozpracovaný state/nonce) a vygeneruje nové session ID.

### `getIdToken(): ?string`
Vrací uložený ID token ze session, pokud existuje.

### `handleBackchannelLogout(string $logoutToken): bool`
Zpracuje backchannel logout požadavek z OIDC providera (např. Keycloak). Validuje JWT logout token a odhlásí lokální session, pokud token odpovídá aktuálnímu uživateli. Vrací `true` pokud byla session odhlášena. Vidí **jen session aktuálního requestu** — provider volá endpoint server-to-server bez cookie, takže při odděleném session storage použij `verifyLogoutToken()`.

### `verifyLogoutToken(string $logoutToken): array`
Ověří podpis logout tokenu proti JWKS providera a jeho claims podle spec (`events`, zákaz `nonce`, přítomnost `sid`/`sub`) a vrátí **verifikované claims**. Se session nijak nemanipuluje. Použij ji, když si session hledáš sám (typicky napříč Redisem) — vrácené claims jsou důvěryhodné, ručně dekódovaný JWT nikdy. Hodí `RuntimeException`, pokud je token nevalidní.

### `decodeJwtPayload(string $jwt): ?array`
Statická pomocná metoda: rozparsuje payload JWT **bez ověření podpisu**. Používej jen na tokeny, které už jsi ověřil, nebo na tokeny z vlastní session (např. ID token uložený v Redisu). Na vstup od klienta nikdy — k tomu je `verifyLogoutToken()`.

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

Token je validován podle [OIDC Back-Channel Logout specifikace](https://openid.net/specs/openid-connect-backchannel-1_0.html). Session se páruje podle `sid` (session ID); `sub` (subject/user ID) se použije jen tehdy, když token `sid` neobsahuje — jinak by odhlášení jedné session shodilo všechny session daného uživatele.

## Zabezpečení

Co knihovna dělá:

- **`state`** — každý authorization request je svázán s konkrétní session. Chrání proti CSRF a authorization code injection (podstrčení cizího `code`).
- **`nonce`** — ID token musí obsahovat `nonce` odpovídající session. Chrání proti replay ID tokenu. Kontrola je explicitní: token bez `nonce` je odmítnut, nejen token s nesprávným `nonce`.
- **Připnutý podpisový algoritmus** — `id_token_signed_response_alg` se posílá v client metadatech, takže verifikátor si zaregistruje `AlgorithmChecker` a přijme jen ten jeden algoritmus. Bez toho žádný allow-list neplatí, algoritmus si vybírá header tokenu a mezi podporovanými je i `none`, jehož `verify()` vrací `true` pro prázdný podpis bez kontroly typu klíče. Krylo to jen to, že JWKS obvykle u klíčů `alg` uvádí. Platí i pro backchannel logout token, ověřuje se stejným builderem.
- **Regenerace session ID** při přihlášení a odhlášení — ochrana proti session fixation.

Co knihovna **nedělá** a co si musíš zajistit sám:

- **PKCE není implementováno.** Pro confidential klienta (se `clientSecret`) je náhradou `nonce`, viz RFC 9700. Public klient touto knihovnou podporovaný není, proto je `clientSecret` povinný.
- **Hlavičky `X-Forwarded-*` se berou bez omezení.** `buildAbsoluteUrl()` jim věří, takže musíš mít nakonfigurovanou trusted proxy (`Nette\Http\RequestFactory::setProxy()`), nebo — bezpečněji — zadat `redirectUri`, `postLogoutRedirectUri` a `backchannelLogoutUri` jako absolutní URL.
- **Backchannel logout nemá ochranu proti replay.** `jti` se nikam neukládá, odposlechnutý `logout_token` lze přehrávat do jeho expirace (vynucené odhlašování).
- **Chybové hlášky neposílej klientovi.** Zprávy z výjimek obsahují detaily verifikace tokenu; na backchannel endpointu vracej jen prázdné 400.

## Klíčové vlastnosti

- Authorization code flow s `state` a `nonce` svázanými se session
- Ověření ID tokenu proti JWKS providera s připnutým algoritmem
- Regenerace session ID při přihlášení a odhlášení
- Front-channel a backchannel logout, včetně ověření logout tokenu
- Obnova tokenů přes refresh token (voláním `refreshToken()`, ne automaticky)
- Správa session v Nette session storage
- Automatické sestavování absolutních URL z relativních cest
- Podpora reverse proxy a Kubernetes Ingress

## Licence

GPL-3.0-or-later — viz [LICENSE](LICENSE).
