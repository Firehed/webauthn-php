<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use UnexpectedValueException;

class WildcardRelyingParty implements RelyingParty
{
    public function __construct(private string $rpId)
    {
        // This should bail if rpId isn't an acceptable registratable domain.
        // To do so, it needs to be compared against an up-to-date public
        // suffix list
    }

    public function permitsRpIdHash(AuthenticatorData $authData): bool
    {
        $expected = hash('sha256', $this->rpId, true);
        return hash_equals($expected, $authData->getRpIdHash()->unwrap());
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
        // TODO: where is secure context enforced? This needs to allow
        // localhost/loopback addresses
        //
        // https://w3c.github.io/webappsec-secure-contexts/
        if ($parts['scheme'] !== 'https') {
            return false;
        }

        $host = $parts['host'];
        if ($host === $this->rpId) {
            return true;
        }
        return str_ends_with(haystack: $host, needle: '.' . $this->rpId);
    }
}
