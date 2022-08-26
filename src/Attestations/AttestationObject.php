<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

/**
 * @internal
 *
 * @see s6.5
 * @link https://www.w3.org/TR/webauthn-2/#sctn-attestation
 */
class AttestationObject implements AttestationObjectInterface
{
    private function __construct(
        private readonly AuthenticatorData $data,
        private readonly AttestationStatementInterface $stmt,
    ) {
    }

    public static function fromCbor(BinaryString $cbor): AttestationObject
    {
        $decoder = new Decoder();
        $decoded = $decoder->decode($cbor->unwrap());

        assert(array_key_exists('fmt', $decoded));
        assert(array_key_exists('attStmt', $decoded));
        assert(array_key_exists('authData', $decoded));

        $stmt = match ($decoded['fmt']) { // @phpstan-ignore-line
            'none' => new None($decoded['attStmt']),
            'fido-u2f' => new FidoU2F($decoded['attStmt']),
        };

        $ad = AuthenticatorData::parse(new BinaryString($decoded['authData']));

        return new AttestationObject($ad, $stmt);
    }

    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->data;
    }

    /**
     * @param BinaryString $clientDataHash the sha256 hash (raw) of clientDataJson
     */
    public function verify(BinaryString $clientDataHash): VerificationResult
    {
        return $this->stmt->verify($this->data, $clientDataHash);
    }
}
