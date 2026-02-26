<?php

namespace Sitmpcz\oidc\Security;

use Contributte\Psr7\Psr7ServerRequestFactory;
use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\ClientInterface;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Issuer\IssuerBuilder;
use Facile\OpenIDClient\Service\AuthenticationService;
use Facile\OpenIDClient\Service\AuthorizationService;
use Facile\OpenIDClient\Service\Builder\AuthorizationServiceBuilder;
use Facile\OpenIDClient\Service\Builder\UserInfoServiceBuilder;
use Facile\OpenIDClient\Token\TokenVerifierBuilder;
use Nette\Http\Request;
use Nette\Http\Session;
use Nette\Http\SessionSection;
use Jose\Component\Core\JWKSet;

final class OpenIDClientService
{
    private AuthorizationService $authService;
    private ClientInterface $client;
    private ?string $postLogoutRedirectUri;
    /** @var string[] */
    private array $scopes;
    private SessionSection $section;

    public function __construct(
        string $issuerUrl,
        string $clientId,
        ?string $clientSecret,
        ?string $redirectUri,
        array $scopes,
        private Request $netteRequest,
        private Session $session,
        ?string $postLogoutRedirectUri = null,
        ?string $backchannelLogoutUri = null
    ) {
        $this->section = $session->getSection('oidc');
        $issuer = (new IssuerBuilder())->build($issuerUrl);

        $redirectUri = $this->buildAbsoluteUrl($redirectUri ?? $netteRequest->getUrl()->getPath());
        $postLogoutRedirectUri = $postLogoutRedirectUri ? $this->buildAbsoluteUrl($postLogoutRedirectUri) : null;
        $backchannelLogoutUri  = $backchannelLogoutUri  ? $this->buildAbsoluteUrl($backchannelLogoutUri)  : null;

        $metadata = [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uris' => [$redirectUri],
            'post_logout_redirect_uris' => $postLogoutRedirectUri ? [$postLogoutRedirectUri] : [],
            ...($backchannelLogoutUri ? [
                'backchannel_logout_uri' => $backchannelLogoutUri,
                'backchannel_logout_session_required' => true,
            ] : []),
        ];

        $clientMetadata = ClientMetadata::fromArray($metadata);

        $this->client = (new ClientBuilder())
            ->setIssuer($issuer)
            ->setClientMetadata($clientMetadata)
            ->build();

        $this->authService = (new AuthorizationServiceBuilder())->build();
        $this->scopes = $scopes;
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
    }

    public function getAuthorizationUrl(): string
    {
        return $this->authService->getAuthorizationUri($this->client, [
            'scope' => implode(' ', $this->scopes),
        ]);
    }

    public function handleCallback(): array
    {
        $psrRequest = Psr7ServerRequestFactory::fromNette(
            $this->netteRequest
        );
        $callbackParams = $this->authService->getCallbackParams($psrRequest, $this->client);
        $tokenSet = $this->authService->callback($this->client, $callbackParams);
        if (!$tokenSet->getIdToken()) {
            throw new \RuntimeException('Unauthorized');
        }
        $userInfoService = (new UserInfoServiceBuilder())->build();

        $userInfo = $userInfoService->getUserInfo($this->client, $tokenSet);
        $this->section->set('userInfo',$userInfo);
        $this->section->set('refreshToken',$tokenSet->getRefreshToken());
        $this->section->set('idToken',$tokenSet->getIdToken());
        return $userInfo;
    }

    public function refreshToken(): bool
    {
        if($this->section->get('refreshToken')){
            try {
                $tokenSet = $this->authService->grant($this->client, [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $this->section->get('refreshToken'),
                ]);
                $this->section->set('refreshToken',$tokenSet->getRefreshToken());
                return true;
            } catch (\RuntimeException $e) {
                return false;
            }

        }
        return false;
    }

    public function getLogoutUrl(?string $idToken = null): string
    {
        $issuer = $this->client->getIssuer();
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

        $params['client_id'] = $this->client->getMetadata()->getClientId();

        return $endSessionEndpoint . '?' . http_build_query($params);
    }

    public function logout(): void
    {
        $this->section->remove('userInfo');
        $this->section->remove('refreshToken');
        $this->section->remove('idToken');
    }

    public function getIdToken(): ?string
    {
        return $this->section->get('idToken');
    }

    /**
     * Zpracuje backchannel logout požadavek z OIDC providera
     *
     * @param string $logoutToken JWT logout token z POST parametru 'logout_token'
     * @return bool True pokud byl logout úspěšný
     * @throws \RuntimeException pokud je token nevalidní
     */
    public function handleBackchannelLogout(string $logoutToken): bool
    {
        try {
            // Ověř logout token
            $tokenVerifier = (new TokenVerifierBuilder())
                ->build();

            $jwt = $tokenVerifier->verify($this->client, $logoutToken);
            $claims = $jwt->claims();

            // Validace logout tokenu podle OIDC specifikace
            // https://openid.net/specs/openid-connect-backchannel-1_0.html

            // 1. Musí obsahovat 'iss' a 'aud'
            if (!$claims->has('iss') || !$claims->has('aud')) {
                throw new \RuntimeException('Invalid logout token: missing iss or aud');
            }

            // 2. Musí obsahovat 'events' s 'http://schemas.openid.net/event/backchannel-logout'
            $events = $claims->get('events');
            if (!isset($events['http://schemas.openid.net/event/backchannel-logout'])) {
                throw new \RuntimeException('Invalid logout token: missing backchannel-logout event');
            }

            // 3. Nesmí obsahovat 'nonce'
            if ($claims->has('nonce')) {
                throw new \RuntimeException('Invalid logout token: nonce is not allowed');
            }

            // 4. Musí obsahovat buď 'sid' nebo 'sub'
            $sid = $claims->get('sid', null);
            $sub = $claims->get('sub', null);

            if (!$sid && !$sub) {
                throw new \RuntimeException('Invalid logout token: missing sid or sub');
            }

            // Najdi a odhlás session podle sid nebo sub
            $currentIdToken = $this->section->get('idToken');
            if ($currentIdToken) {
                // Dekóduj aktuální ID token pro porovnání
                $currentJwt = $tokenVerifier->verify($this->client, $currentIdToken);
                $currentClaims = $currentJwt->claims();

                // Porovnej podle sid (session ID) nebo sub (subject/user ID)
                $shouldLogout = ($sid && $currentClaims->has('sid') && $currentClaims->get('sid') === $sid)
                    || ($sub && $currentClaims->has('sub') && $currentClaims->get('sub') === $sub);

                if ($shouldLogout) {
                    $this->logout();
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to process backchannel logout: ' . $e->getMessage(), 0, $e);
        }
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
        $scheme = $forwardedProto ?? $url->getScheme();

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