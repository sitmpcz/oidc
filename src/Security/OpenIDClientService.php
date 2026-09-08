<?php

namespace Sitmpcz\oidc\Security;

use Contributte\Psr7\Psr7ServerRequestFactory;
use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\ClientInterface;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Issuer\IssuerBuilder;
use Facile\OpenIDClient\Service\AuthorizationService;
use Facile\OpenIDClient\Service\Builder\AuthorizationServiceBuilder;
use Facile\OpenIDClient\Service\Builder\UserInfoServiceBuilder;
use Facile\OpenIDClient\Session\AuthSession;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilder;
use function Facile\OpenIDClient\parse_callback_params;
use Nette\Http\Request;
use Nette\Http\Session;
use Nette\Http\SessionSection;

final class OpenIDClientService
{
    private ?AuthorizationService $authService = null;
    private ?ClientInterface $client = null;
    private ?string $postLogoutRedirectUri;
    /** @var string[] */
    private array $scopes;
    private SessionSection $section;
    private Session $session;
    private string $issuerUrl;
    private array $clientMetadataArray;

    public function __construct(
        string                   $issuerUrl,
        string                   $clientId,
        string                   $clientSecret,
        string                   $redirectUri,
        array                    $scopes,
        private readonly Request $netteRequest,
        Session                  $session,
        ?string                  $postLogoutRedirectUri = null,
        ?string                  $backchannelLogoutUri = null,
        string                   $idTokenSignedResponseAlg = 'EdDSA'
    ) {
        $this->session = $session;
        $this->section = $session->getSection('oidc');

        $redirectUri = $this->buildAbsoluteUrl($redirectUri);
        $postLogoutRedirectUri = $postLogoutRedirectUri ? $this->buildAbsoluteUrl($postLogoutRedirectUri) : null;
        $backchannelLogoutUri  = $backchannelLogoutUri  ? $this->buildAbsoluteUrl($backchannelLogoutUri)  : null;

        $this->clientMetadataArray = [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            // Pinning the algorithm registers an AlgorithmChecker in the verifier.
            // Without it the verifier accepts any alg the provider's JWKS allows - including "none".
            'id_token_signed_response_alg' => $idTokenSignedResponseAlg,
            'redirect_uris' => [$redirectUri],
            'post_logout_redirect_uris' => $postLogoutRedirectUri ? [$postLogoutRedirectUri] : [],
            ...($backchannelLogoutUri ? [
                'backchannel_logout_uri' => $backchannelLogoutUri,
                'backchannel_logout_session_required' => true,
            ] : []),
        ];

        $this->issuerUrl = $issuerUrl;
        $this->scopes = $scopes;
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
    }

    // lazy load AuthorizationService
    private function getAuthService(): AuthorizationService
    {
        if (is_null($this->authService)) {
            $this->authService = (new AuthorizationServiceBuilder())->build();
        }
        return $this->authService;
    }

    // lazy load ClientInterface
    private function getClient(): ClientInterface
    {
        if (is_null($this->client)) {
            $issuer = (new IssuerBuilder())->build($this->issuerUrl);
            $clientMetadata = ClientMetadata::fromArray($this->clientMetadataArray);
            $this->client = (new ClientBuilder())
                ->setIssuer($issuer)
                ->setClientMetadata($clientMetadata)
                ->build();
        }
        return $this->client;
    }


    public function getAuthorizationUrl(): string
    {
        $state = $this->generateRandomValue();
        $nonce = $this->generateRandomValue();

        // Bind the authorization request to this browser session
        $this->section->set('authState', $state);
        $this->section->set('authNonce', $nonce);

        return $this->getAuthService()->getAuthorizationUri($this->getClient(), [
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'nonce' => $nonce,
        ]);
    }

    public function handleCallback(): array
    {
        $expectedState = $this->section->get('authState');
        $expectedNonce = $this->section->get('authNonce');

        // One-shot values - drop them before any further processing so a callback
        // cannot be replayed against the same session
        $this->section->remove('authState');
        $this->section->remove('authNonce');

        if (!is_string($expectedState) || $expectedState === '' || !is_string($expectedNonce) || $expectedNonce === '') {
            throw new \RuntimeException('No authorization request pending in this session (session expired or login was not started here)');
        }

        $psrRequest = Psr7ServerRequestFactory::fromNette(
            $this->netteRequest
        );

        // Fail fast, before any network call to the provider
        $rawParams = parse_callback_params($psrRequest);
        if (array_key_exists('state', $rawParams)) {
            $this->assertStateMatches($expectedState, $rawParams['state']);
        }

        $callbackParams = $this->getAuthService()->getCallbackParams($psrRequest, $this->getClient());

        // Authoritative check on the processed params (covers signed responses,
        // where the raw request carries no readable state)
        $this->assertStateMatches($expectedState, $callbackParams['state'] ?? null);

        $authSession = AuthSession::fromArray([
            'state' => $expectedState,
            'nonce' => $expectedNonce,
        ]);

        $tokenSet = $this->getAuthService()->callback($this->getClient(), $callbackParams, null, $authSession);
        if (!$tokenSet->getIdToken()) {
            throw new \RuntimeException('Unauthorized');
        }

        // The verifier's NonceChecker only runs when the claim is actually present,
        // so an ID token with no nonce at all would pass silently - require it here.
        $receivedNonce = $tokenSet->claims()['nonce'] ?? null;
        if (!is_string($receivedNonce) || !hash_equals($expectedNonce, $receivedNonce)) {
            throw new \RuntimeException('Nonce mismatch - possible ID token replay');
        }

        $userInfoService = (new UserInfoServiceBuilder())->build();

        $userInfo = $userInfoService->getUserInfo($this->getClient(), $tokenSet);

        // Prevent session fixation: the pre-authentication session ID must not survive login
        $this->regenerateSessionId();

        $this->section->set('userInfo',$userInfo);
        $this->section->set('refreshToken',$tokenSet->getRefreshToken());
        $this->section->set('idToken',$tokenSet->getIdToken());
        return $userInfo;
    }

    public function refreshToken(): bool
    {
        $refreshToken = $this->section->get('refreshToken');

        if (!is_string($refreshToken) || $refreshToken === '') {
            return false;
        }

        try {
            // refresh() na rozdíl od grant() ověří ID token z odpovědi
            $tokenSet = $this->getAuthService()->refresh($this->getClient(), $refreshToken);
        } catch (\RuntimeException | \InvalidArgumentException $e) {
            return false;
        }

        // Provider nemusí při rotaci nový refresh token vrátit. Pak platí dál
        // ten stávající - přepsat ho na null by odstřihlo všechny další refreshe.
        $newRefreshToken = $tokenSet->getRefreshToken();
        if ($newRefreshToken !== null) {
            $this->section->set('refreshToken', $newRefreshToken);
        }

        // Bez tohohle zůstane v session ID token s původním exp a getLogoutUrl()
        // by pak posílal expirovaný id_token_hint
        $newIdToken = $tokenSet->getIdToken();
        if ($newIdToken !== null) {
            $this->section->set('idToken', $newIdToken);
        }

        return true;
    }

    public function getLogoutUrl(?string $idToken = null): string
    {
        $issuer = $this->getClient()->getIssuer();
        $endSessionEndpoint = $issuer->getMetadata()->get('end_session_endpoint');

        if (!$endSessionEndpoint) {
            throw new \RuntimeException('Provider does not support logout (end_session_endpoint not found)');
        }

        $params = [];

        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }

        if ($this->postLogoutRedirectUri) {
            $params['post_logout_redirect_uri'] = $this->postLogoutRedirectUri;
        }

        $params['client_id'] = $this->getClient()->getMetadata()->getClientId();

        // end_session_endpoint už může mít vlastní query string
        $separator = str_contains($endSessionEndpoint, '?') ? '&' : '?';

        return $endSessionEndpoint . $separator . http_build_query($params);
    }

    public function logout(): void
    {
        $this->section->remove('userInfo');
        $this->section->remove('refreshToken');
        $this->section->remove('idToken');
        $this->section->remove('authState');
        $this->section->remove('authNonce');
        $this->regenerateSessionId();
    }

    /**
     * @param mixed $received
     * @throws \RuntimeException pokud state nesouhlasí
     */
    private function assertStateMatches(string $expected, $received): void
    {
        if (!is_string($received) || !hash_equals($expected, $received)) {
            throw new \RuntimeException('State mismatch - possible CSRF or authorization code injection');
        }
    }

    /**
     * Vytvoří kryptograficky náhodnou hodnotu pro state/nonce (URL-safe)
     */
    private function generateRandomValue(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Vygeneruje nové session ID, pokud je session aktivní (ochrana proti session fixation)
     */
    private function regenerateSessionId(): void
    {
        if ($this->session->isStarted()) {
            $this->session->regenerateId();
        }
    }

    public function getIdToken(): ?string
    {
        return $this->section->get('idToken');
    }

    /**
     * Ověří podpis a claims backchannel logout tokenu a vrátí verifikované claims.
     * Se session nijak nemanipuluje - použij, když si session hledáš sám
     * (např. napříč Redisem). Vrácené claims jsou důvěryhodné, ručně dekódované
     * claims z JWT nikdy nejsou.
     *
     * @param string $logoutToken JWT logout token z POST parametru 'logout_token'
     * @return array<string, mixed> Verifikované claims tokenu
     * @throws \RuntimeException pokud je token nevalidní
     */
    public function verifyLogoutToken(string $logoutToken): array
    {
        try {
            // Ověř podpis a standardní claims logout tokenu
            $verifier = (new IdTokenVerifierBuilder())->build($this->getClient());
            $claims = $verifier->verify($logoutToken);

            // Validace logout tokenu podle OIDC specifikace
            // https://openid.net/specs/openid-connect-backchannel-1_0.html

            // 1. Musí obsahovat 'events' s 'http://schemas.openid.net/event/backchannel-logout'
            $events = $claims['events'] ?? null;
            if (!is_array($events) || !isset($events['http://schemas.openid.net/event/backchannel-logout'])) {
                throw new \RuntimeException('Invalid logout token: missing backchannel-logout event');
            }

            // 2. Nesmí obsahovat 'nonce'
            if (isset($claims['nonce'])) {
                throw new \RuntimeException('Invalid logout token: nonce is not allowed');
            }

            // 3. Musí obsahovat buď 'sid' nebo 'sub'
            if (!isset($claims['sid']) && !isset($claims['sub'])) {
                throw new \RuntimeException('Invalid logout token: missing sid or sub');
            }

            return $claims;
        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to process backchannel logout: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Zpracuje backchannel logout požadavek z OIDC providera pro aktuální session.
     *
     * Pozor: vidí jen session aktuálního requestu. Provider volá endpoint
     * server-to-server bez cookie, takže při odděleném session storage (Redis)
     * si session musíš najít sám - použij k tomu verifyLogoutToken().
     *
     * @param string $logoutToken JWT logout token z POST parametru 'logout_token'
     * @return bool True pokud byla aktuální session odhlášena
     * @throws \RuntimeException pokud je token nevalidní
     */
    public function handleBackchannelLogout(string $logoutToken): bool
    {
        $claims = $this->verifyLogoutToken($logoutToken);

        try {
            $sid = $claims['sid'] ?? null;
            $sub = $claims['sub'] ?? null;

            // Porovnej s aktuální session — dekóduj uložený ID token bez re-verifikace
            // (ID token v session může být expirovaný, ale sid/sub jsou stále platné)
            $currentIdToken = $this->section->get('idToken');
            if (is_string($currentIdToken) && $currentIdToken !== '') {
                $currentClaims = self::decodeJwtPayload($currentIdToken);

                if ($currentClaims !== null) {
                    $currentSid = $currentClaims['sid'] ?? null;
                    $currentSub = $currentClaims['sub'] ?? null;

                    if ($sid !== null) {
                        $shouldLogout = $currentSid === $sid;
                    } else {
                        $shouldLogout = $sub !== null && $currentSub === $sub;
                    }

                    if ($shouldLogout) {
                        $this->logout();
                        return true;
                    }
                }
            }

            return false;
        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to process backchannel logout: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Rozparsuje payload JWT bez ověření podpisu.
     *
     * Použitelné jen na tokeny, které už jsi ověřil, nebo na tokeny z vlastní
     * session. Na vstup od klienta nikdy - k tomu je verifyLogoutToken().
     *
     * @return array<string, mixed>|null null pokud payload nelze rozparsovat
     */
    public static function decodeJwtPayload(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        $b64 = strtr($parts[1], '-_', '+/');
        $b64 = str_pad($b64, strlen($b64) + (4 - strlen($b64) % 4) % 4, '=');
        $payload = base64_decode($b64, true);
        if ($payload === false) {
            return null;
        }

        $claims = json_decode($payload, true);

        return is_array($claims) ? $claims : null;
    }

    /**
     * Vytvoří absolutní URL z relativní cesty nebo vrátí původní pokud už je absolutní
     */
    private function buildAbsoluteUrl(string $path): string
    {
        // Pokud už je absolutní URL (začíná http:// nebo https://), vrať ji
        if (preg_match('~^https?://~i', $path)) {
            return $path;
        }

        $url = $this->netteRequest->getUrl();

        // Detekce reverse proxy - preferuj X-Forwarded-Proto před skutečným schématem
        $forwardedProto = $this->netteRequest->getHeader('X-Forwarded-Proto');

        // Multiple proxy hops
        if ($forwardedProto !== null) {
            $forwardedProto = trim(explode(',', $forwardedProto)[0]);
        }

        $scheme = $forwardedProto !== null && $forwardedProto !== '' ? $forwardedProto : $url->getScheme();

        // X-Forwarded-Host pro host za proxy
        $host = $this->netteRequest->getHeader('X-Forwarded-Host') ?? $url->getHost();

        // X-Forwarded-Port pro port za proxy
        $forwardedPort = $this->netteRequest->getHeader('X-Forwarded-Port');

        $standardPort = $scheme === 'https' ? 443 : 80;

        if ($forwardedPort) {
            $port = (int) $forwardedPort;
            // Pokud X-Forwarded-Port je standardní port pro schéma, ignoruj ho
            // (K8s Ingress často nastavuje X-Forwarded-Port: 80 i pro HTTPS)
            if (($scheme === 'https' && $port === 80) || ($scheme === 'http' && $port === 443)) {
                $port = $standardPort;
            }
        } elseif ($forwardedProto) {
            // Za reverse proxy bez explicitního portu - použij standardní port pro schéma
            $port = $standardPort;
        } else {
            // Není proxy - použij skutečný port
            $port = $url->getPort();
        }

        // Přidej port pouze pokud není standardní (80 pro HTTP, 443 pro HTTPS)
        $portPart = '';
        if (($scheme === 'http' && $port !== 80) || ($scheme === 'https' && $port !== 443)) {
            $portPart = ':' . $port;
        }

        // Ujisti se, že cesta začíná lomítkem
        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }

        return $scheme . '://' . $host . $portPart . $path;
    }
}
