<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use InvalidArgumentException;

/**
 * This uses an explicit allowlist of valid origins for a given Relying Party
 * ID to perform matching.
 */
class MultiOriginRelyingParty implements RelyingParty
{
    /**
     * @param string[] $origins
     */
    public function __construct(
        private array $origins,
        private string $rpId,
    ) {
        foreach ($origins as $origin) {
            $host = parse_url($origin, PHP_URL_HOST);
            if (!str_ends_with($host, $rpId)) {
                throw new InvalidArgumentException(sprintf(
                    'Origin %s cannot work with rpId %s',
                    $origin,
                    $rpId,
                ));
            }
        }
    }

    /**
     * Used by steps 7.1.9 and 7.2.13
     *
     * @internal
     */
    public function matchesOrigin(string $clientDataOrigin): bool
    {
        $allowed = false;
        // Keep this remotely resistant to timing attacks
        foreach ($this->origins as $origin) {
            if (hash_equals($origin, $clientDataOrigin)) {
                $allowed = true;
            }
        }
        return $allowed;
    }

    /**
     * Used by steps 7.1.13 and 7.2.15
     *
     * @internal
     */
    public function permitsRpIdHash(AuthenticatorData $authData): bool
    {
        $expected = hash('sha256', $this->rpId, true);
        return hash_equals($expected, $authData->getRpIdHash()->unwrap());
    }
}
