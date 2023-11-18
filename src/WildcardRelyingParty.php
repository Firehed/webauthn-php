<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use UnexpectedValueException;

class WildcardRelyingParty implements RelyingPartyInterface
{
    private bool $isLocal;

    /**
     * @param string $rpId The rpId for all origins used by the Relying Party.
     * Any origin in a secure context aligned with the specified rpId will be
     * permitted.
     */
    public function __construct(private string $rpId)
    {
        // This should bail if rpId isn't an acceptable registratable domain.
        // To do so, it needs to be compared against an up-to-date public
        // suffix list

        // Allow non-https origins locally
        // https://w3c.github.io/webappsec-secure-contexts/
        $this->isLocal = match (true) {
            $rpId === 'localhost' => true,
            $rpId === '127.0.0.1' => true,
            // TODO: ipv6 loopback(s)
            // $rpId === '::1' => true,
            str_ends_with('.localhost', $rpId) => true,
            default => false,
        };
    }

    public function matchesOrigin(string $clientDataOrigin): bool
    {
        $parts = parse_url($clientDataOrigin);
        if ($parts === false) {
            throw new UnexpectedValueException();
        }
        if (!array_key_exists('scheme', $parts)) {
            throw new UnexpectedValueException();
        }
        if (!array_key_exists('host', $parts)) {
            throw new UnexpectedValueException();
        }
        if ($parts['scheme'] !== 'https' && !$this->isLocal) {
            return false;
        }

        $host = $parts['host'];
        if ($host === $this->rpId) {
            return true;
        }
        return str_ends_with(haystack: $host, needle: '.' . $this->rpId);
    }

    public function permitsRpIdHash(AuthenticatorData $authData): bool
    {
        $expected = hash('sha256', $this->rpId, true);
        return hash_equals($expected, $authData->getRpIdHash()->unwrap());
    }
}
