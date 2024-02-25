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
    private Format $format;
    /** @var mixed[] */
    private array $attStmt;

    public function __construct(
        private readonly BinaryString $rawCbor,
    ) {
        $decoder = new Decoder();
        // 7.1.12
        $decoded = $decoder->decode($rawCbor->unwrap());

        assert(array_key_exists('fmt', $decoded));
        assert(array_key_exists('attStmt', $decoded));
        assert(array_key_exists('authData', $decoded));

        // 7.1.21
        $this->format = Format::from($decoded['fmt']);

        $this->attStmt = $decoded['attStmt'];

        $this->data = AuthenticatorData::parse(new BinaryString($decoded['authData']));
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
        $statement = match ($this->format) {
            Format::Apple => new Apple($this->attStmt),
            Format::None => new None($this->attStmt),
            Format::Packed => new Packed($this->attStmt),
            Format::U2F => new FidoU2F($this->attStmt),
            default => new LibraryUnsupported(),
        };
        return $statement->verify($this->data, $clientDataHash);
    }

    public function getCbor(): BinaryString
    {
        return $this->rawCbor;
    }
}
