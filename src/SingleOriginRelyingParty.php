<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class SingleOriginRelyingParty implements RelyingPartyInterface
{
    private string $id;

    /**
     * @param string $origin The origin of the server. This needs to match
     * what's in the browser's address bar; i.e. it must included the protocol
     * (http(s)), the complete host, and the port if a value other than the
     * default.
     */
    public function __construct(private string $origin)
    {
        $host = parse_url($this->origin, PHP_URL_HOST);
        assert(is_string($host));
        $this->id = $host;
    }

    public function matchesOrigin(string $clientDataOrigin): bool
    {
        return hash_equals($this->origin, $clientDataOrigin);
    }

    public function permitsRpIdHash(AuthenticatorData $authData): bool
    {
        $expected = hash('sha256', $this->id, true);
        return hash_equals($expected, $authData->getRpIdHash()->unwrap());
    }
}
