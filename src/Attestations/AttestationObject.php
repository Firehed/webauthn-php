<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

/**
 * @see s6.5
 * @link https://www.w3.org/TR/webauthn-2/#sctn-attestation
 */
class AttestationObject
{
    private function __construct(
        public readonly AuthenticatorData $data,
        public readonly AttestationStatementInterface $stmt,
    ) {
    }

    public static function fromCbor(BinaryString $cbor): AttestationObject
    {
        $decoder = new Decoder();
        $decoded = $decoder->decode($cbor->unwrap());

        assert(array_key_exists('fmt', $decoded));
        assert(array_key_exists('attStmt', $decoded));
        assert(array_key_exists('authData', $decoded));

        $stmt = match ($decoded['fmt']) {
            'none' => new None($decoded['attStmt']),
            'fido-u2f' => new FidoU2F($decoded['attStmt']),
        };

        $ad = AuthenticatorData::parse(new BinaryString($decoded['authData']));

        return new AttestationObject($ad, $stmt);
    }

    /**
     * @param string $hash the sha256 hash (raw) of clientDataJson
     */
    public function verify(BinaryString $clientDataHash)
    {
        return $this->stmt->verify($this->data, $clientDataHash);
    }
}
