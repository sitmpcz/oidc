<?php

namespace Sitmpcz\oidc\Security;

use Facile\JoseVerifier\AbstractTokenVerifier;
use Facile\JoseVerifier\Exception\InvalidTokenException;
use Facile\JoseVerifier\IdTokenVerifierInterface;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Obal upstream verifieru, který před ověřením zkontroluje alg z hlavičky
 * tokenu proti allow-listu a pak ho verifieru připne přes withExpectedAlg().
 * Upstream tak dál registruje AlgorithmChecker - bez připnutého algoritmu by
 * prošlo i "none".
 */
final class AlgAllowListIdTokenVerifier implements IdTokenVerifierInterface
{
    /**
     * @param list<string> $allowedAlgs
     */
    public function __construct(
        private readonly IdTokenVerifierInterface $inner,
        private readonly array $allowedAlgs,
    ) {
        // withExpectedAlg() není součástí interface - bez něj nejde algoritmus připnout
        if (!$inner instanceof AbstractTokenVerifier) {
            throw new \InvalidArgumentException('Inner verifier must extend ' . AbstractTokenVerifier::class);
        }
    }

    public function withAccessToken(?string $accessToken): self
    {
        return new self($this->inner->withAccessToken($accessToken), $this->allowedAlgs);
    }

    public function withCode(?string $code): self
    {
        return new self($this->inner->withCode($code), $this->allowedAlgs);
    }

    public function withState(?string $state): self
    {
        return new self($this->inner->withState($state), $this->allowedAlgs);
    }

    public function withNonce(?string $nonce): self
    {
        return new self($this->inner->withNonce($nonce), $this->allowedAlgs);
    }

    public function withMaxAge(?int $maxAge): self
    {
        return new self($this->inner->withMaxAge($maxAge), $this->allowedAlgs);
    }

    public function verify(string $jwt): array
    {
        $alg = $this->readAlg($jwt);

        if (!in_array($alg, $this->allowedAlgs, true)) {
            throw new InvalidTokenException(sprintf('ID token algorithm "%s" is not allowed', $alg));
        }

        /** @var AbstractTokenVerifier $inner */
        $inner = $this->inner;

        return $inner->withExpectedAlg($alg)->verify($jwt);
    }

    private function readAlg(string $jwt): string
    {
        // Šifrované tokeny (JWE, 5 částí) knihovna nepodporuje, hlavička by tu nesla alg klíče
        if (substr_count($jwt, '.') !== 2) {
            throw new InvalidTokenException('Invalid JWT provided');
        }

        try {
            $jws = (new CompactSerializer())->unserialize($jwt);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException('Invalid JWT provided', 0, $e);
        }

        $alg = $jws->getSignature(0)->getProtectedHeader()['alg'] ?? null;

        if (!is_string($alg)) {
            throw new InvalidTokenException('Invalid JWT provided: missing alg');
        }

        return $alg;
    }
}
