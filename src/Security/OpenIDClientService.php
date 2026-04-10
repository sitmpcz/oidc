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
use Facile\OpenIDClient\Token\IdTokenVerifierBuilder;
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
    private string $issuerUrl;
    private array $clientMetadataArray;

    public function __construct(
        string                   $issuerUrl,
        string                   $clientId,
        ?string                  $clientSecret,
        ?string                  $redirectUri,
        array                    $scopes,
        private readonly Request $netteRequest,
        Session                  $session,
        ?string                  $postLogoutRedirectUri = null,
        ?string                  $backchannelLogoutUri = null
    ) {
        $this->section = $session->getSection('oidc');

        $redirectUri = $this->buildAbsoluteUrl($redirectUri ?? $netteRequest->getUrl()->getPath());
        $postLogoutRedirectUri = $postLogoutRedirectUri ? $this->buildAbsoluteUrl($postLogoutRedirectUri) : null;
        $backchannelLogoutUri  = $backchannelLogoutUri  ? $this->buildAbsoluteUrl($backchannelLogoutUri)  : null;

        $this->clientMetadataArray = [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
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
        return $this->getAuthService()->getAuthorizationUri($this->getClient(), [
            'scope' => implode(' ', $this->scopes),
        ]);
    }

    public function handleCallback(): array
    {
        $psrRequest = Psr7ServerRequestFactory::fromNette(
            $this->netteRequest
        );
        $callbackParams = $this->getAuthService()->getCallbackParams($psrRequest, $this->getClient());
        $tokenSet = $this->getAuthService()->callback($this->getClient(), $callbackParams);
        if (!$tokenSet->getIdToken()) {
            throw new \RuntimeException('Unauthorized');
        }
        $userInfoService = (new UserInfoServiceBuilder())->build();

        $userInfo = $userInfoService->getUserInfo($this->getClient(), $tokenSet);
        $this->section->set('userInfo',$userInfo);
        $this->section->set('refreshToken',$tokenSet->getRefreshToken());
        $this->section->set('idToken',$tokenSet->getIdToken());
        return $userInfo;
    }

    public function refreshToken(): bool
    {
        if($this->section->get('refreshToken')){
            try {
                $tokenSet = $this->getAuthService()->grant($this->getClient(), [
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
            // Ověř podpis a standardní claims logout tokenu
            $verifier = (new IdTokenVerifierBuilder())->build($this->getClient());
            $claims = $verifier->verify($logoutToken);

            // Validace logout tokenu podle OIDC specifikace
            // https://openid.net/specs/openid-connect-backchannel-1_0.html

            // 1. Musí obsahovat 'events' s 'http://schemas.openid.net/event/backchannel-logout'
            $events = $claims['events'] ?? null;
            if (!isset($events['http://schemas.openid.net/event/backchannel-logout'])) {
                throw new \RuntimeException('Invalid logout token: missing backchannel-logout event');
            }

            // 2. Nesmí obsahovat 'nonce'
            if (isset($claims['nonce'])) {
                throw new \RuntimeException('Invalid logout token: nonce is not allowed');
            }

            // 3. Musí obsahovat buď 'sid' nebo 'sub'
            $sid = $claims['sid'] ?? null;
            $sub = $claims['sub'] ?? null;

            if (!$sid && !$sub) {
                throw new \RuntimeException('Invalid logout token: missing sid or sub');
            }

            // Porovnej s aktuální session — dekóduj uložený ID token bez re-verifikace
            // (ID token v session může být expirovaný, ale sid/sub jsou stále platné)
            $currentIdToken = $this->section->get('idToken');
            if ($currentIdToken) {
                $parts = explode('.', $currentIdToken);
                $b64 = strtr($parts[1] ?? '', '-_', '+/');
                $b64 = str_pad($b64, strlen($b64) + (4 - strlen($b64) % 4) % 4, '=');
                $currentClaims = json_decode(base64_decode($b64), true);

                if (is_array($currentClaims)) {
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
