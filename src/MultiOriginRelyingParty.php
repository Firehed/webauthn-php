<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use InvalidArgumentException;

use function hash;
use function hash_equals;
use function is_string;
use function parse_url;
use function sprintf;

/**
 * This uses an explicit allowlist of valid origins for a given Relying Party
 * ID to perform matching.
 */
class MultiOriginRelyingParty implements RelyingPartyInterface
{
    /**
     * @param string[] $origins A list of origins that the RP supports
     * @param string $rpId The common rpId for all allowed origins
     */
    public function __construct(
        private array $origins,
        private string $rpId,
    ) {
        foreach ($origins as $origin) {
            $host = parse_url($origin, PHP_URL_HOST);
            if (!is_string($host)) {
                throw new InvalidArgumentException(
                    sprintf('Origin %s cannot be parsed', $origin),
                );
            }
            // exact match
            if ($host === $rpId) {
                continue;
            }
            // subdomain
            if (!str_ends_with($host, '.' . $rpId)) {
                throw new InvalidArgumentException(sprintf(
                    'Origin %s cannot work with rpId %s',
                    $origin,
                    $rpId,
                ));
            }
        }
    }

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

    public function permitsRpIdHash(AuthenticatorData $authData): bool
    {
        $expected = hash('sha256', $this->rpId, true);
        return hash_equals($expected, $authData->getRpIdHash()->unwrap());
    }
}
