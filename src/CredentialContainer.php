<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api
 */
class CredentialContainer
{
    /**
     * @param CredentialInterface[] $credentials
     */
    public function __construct(private array $credentials)
    {
    }

    public function findCredentialUsedByResponse(Responses\AssertionInterface $response): ?CredentialInterface
    {
        $responseCredentialId = $response->getUsedCredentialId();

        // This could be done with an array_reduce, but a simple loop is
        // clearer here (and in some cases faster)
        foreach ($this->credentials as $credential) {
            if ($credential->getId()->equals($responseCredentialId)) {
                return $credential;
            }
        }
        return null;
    }

    /**
     * Returns a list of base64-encoded ids, intended to be passed to end-users
     * via javascript for use in CreateOptions.publicKey.allowCredentials
     *
     * TODO: improve description
     *
     * @return string[]
     */
    public function getBase64Ids(): array
    {
        return array_map(fn ($c) => base64_encode($c->getId()->unwrap()), $this->credentials);
    }
}
