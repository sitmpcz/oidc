<?php

namespace Sitmpcz\oidc\Security;

use Facile\JoseVerifier\IdTokenVerifierInterface;
use Facile\OpenIDClient\Client\ClientInterface;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilder;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilderInterface;

/**
 * Builder ID token verifieru s allow-listem asymetrických algoritmů.
 *
 * Upstream umí připnout jen jeden algoritmus (id_token_signed_response_alg).
 * Tady se povolí celý seznam, ale jen asymetrické algoritmy - "none" a HS*
 * (podepsané client_secretem, který zná i klient) projít nemůžou.
 */
final class AsymmetricIdTokenVerifierBuilder implements IdTokenVerifierBuilderInterface
{
    public const SUPPORTED_ALGS = [
        'RS256', 'RS384', 'RS512',
        'PS256', 'PS384', 'PS512',
        'ES256', 'ES384', 'ES512',
        'EdDSA',
    ];

    /** @var list<string> */
    private array $allowedAlgs;

    /**
     * @param list<string> $allowedAlgs
     * @throws \InvalidArgumentException pokud je seznam prázdný nebo obsahuje nepodporovaný algoritmus
     */
    public function __construct(array $allowedAlgs = self::SUPPORTED_ALGS)
    {
        if ($allowedAlgs === []) {
            throw new \InvalidArgumentException('At least one ID token signing algorithm must be allowed');
        }

        foreach ($allowedAlgs as $alg) {
            if (!in_array($alg, self::SUPPORTED_ALGS, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'Unsupported ID token signing algorithm "%s", allowed: %s',
                    $alg,
                    implode(', ', self::SUPPORTED_ALGS)
                ));
            }
        }

        $this->allowedAlgs = array_values(array_unique($allowedAlgs));
    }

    public function build(ClientInterface $client): IdTokenVerifierInterface
    {
        return new AlgAllowListIdTokenVerifier(
            (new IdTokenVerifierBuilder())->build($client),
            $this->resolveAlgs($client)
        );
    }

    /**
     * Zúží allow-list na algoritmy, které provider inzeruje v discovery
     * (id_token_signing_alg_values_supported). Discovery jen zužuje - co není
     * v allow-listu, nepovolí ani provider.
     *
     * @return list<string>
     */
    private function resolveAlgs(ClientInterface $client): array
    {
        $advertised = $client->getIssuer()->getMetadata()->get('id_token_signing_alg_values_supported');

        // Pole je v discovery povinné, ale když chybí, zůstane allow-list beze změny
        if (!is_array($advertised)) {
            return $this->allowedAlgs;
        }

        $algs = array_values(array_intersect($this->allowedAlgs, $advertised));

        if ($algs === []) {
            throw new \RuntimeException(sprintf(
                'Provider advertises no allowed ID token signing algorithm (advertised: %s, allowed: %s)',
                implode(', ', array_filter($advertised, 'is_string')),
                implode(', ', $this->allowedAlgs)
            ));
        }

        return $algs;
    }
}
