<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api
 */
class RelyingParty
{
    /**
     * @param string $origin The origin of the server. This needs to match
     * what's in the browser's address bar; i.e. it must included the protocol
     * (http(s)), the complete host, and the port if a value other than the
     * default.
     */
    public function __construct(
        private string $origin,
    ) {
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    /**
     * TODO: getIds(): string[] <- you can walk up to the regsirable domain
     *
     * @link https://www.w3.org/TR/webauthn-2/#rp-id
     */
    public function getId(): string
    {
        // """
        // By default, the RP ID for a WebAuthn operation is set to the
        // caller’s origin's effective domain. This default MAY be overridden by
        // the caller, as long as the caller-specified RP ID value is a
        // registrable domain suffix of or is equal to the caller’s origin's
        // effective domain.
        // """
        // tl;dr ~
        // a) this should default to the host (it does)
        // b) if publicKey.rp.id is overridden, this must match
        $host = parse_url($this->origin, PHP_URL_HOST);
        assert(is_string($host));
        return $host;
    }
}
