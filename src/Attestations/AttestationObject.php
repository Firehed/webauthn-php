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
    private readonly AuthenticatorData $data;
    private readonly AttestationStatementInterface $stmt;

    public function __construct(
        private readonly BinaryString $rawCbor,
    ) {
        $decoder = new Decoder();
        $decoded = $decoder->decode($rawCbor->unwrap());

        assert(array_key_exists('fmt', $decoded));
        assert(array_key_exists('attStmt', $decoded));
        assert(array_key_exists('authData', $decoded));

        $stmt = match (Format::tryFrom($decoded['fmt'])) { // @phpstan-ignore-line
            Format::Apple => new Apple($decoded['attStmt']),
            Format::None => new None($decoded['attStmt']),
            Format::Packed => new Packed($decoded['attStmt']),
            Format::U2F => new FidoU2F($decoded['attStmt']),
        };

        $ad = AuthenticatorData::parse(new BinaryString($decoded['authData']));

        $this->data = $ad;
        $this->stmt = $stmt;
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

    public function getCbor(): BinaryString
    {
        return $this->rawCbor;
    }
}
