<?php

namespace Firehed\WebAuthn;

use Firehed\CBOR\Decoder;

/**
 * @internal
 */
class AttestationParser
{
    /**
     * Takes the binary CBOR string that comes out of
     * `navigator.credentials.create(...)`'s  .response.attestationObject and
     * decodes it into an internal data format.
     */
    public static function parse(BinaryString $cbor): Attestations\AttestationObject
    {
        $decoder = new Decoder();
        $decoded = $decoder->decode($cbor->unwrap());

        assert(array_key_exists('fmt', $decoded));
        assert(array_key_exists('attStmt', $decoded));
        assert(array_key_exists('authData', $decoded));

        $stmt = match ($decoded['fmt']) {
            'none' => new Attestations\None($decoded['attStmt']),
            'fido-u2f' => new Attestations\FidoU2F($decoded['attStmt']),
        };

        $ad = AuthenticatorData::parse(new BinaryString($decoded['authData']));
        return new Attestations\AttestationObject($ad, $stmt);
    }
}
