<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Note: nearly all methods on this interface are considered internal. The only
 * interaction in user-space is in combination with the Codec and getting the
 * id in a binary-free format.
 */
interface CredentialInterface
{
    /**
     * Returns (optionally) an AttestationObject and the raw ClientDataJSON
     * that was signed by that attestation. These are always used as a pair.
     *
     * @internal
     *
     * @return ?array{Attestations\AttestationObjectInterface, BinaryString}
     */
    public function getAttestationData(): ?array;

    /**
     * @internal
     *
     * Retreives the COSE key in raw CBOR format
     */
    public function getCoseCbor(): BinaryString;

    /**
     * @internal
     */
    public function getId(): BinaryString;

    /**
     * @internal
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface;

    /**
     * @internal
     */
    public function getSignCount(): int;

    /**
     * @api
     *
     * Returns an encoded version of the credential's id guaranteed to return
     * no binary characters.
     */
    public function getStorageId(): string;

    /**
     * @internal
     *
     * @return Enums\AuthenticatorTransport[]
     */
    public function getTransports(): array;

    /**
     * @internal
     */
    public function isBackupEligible(): bool;

    /**
     * @internal
     */
    public function isBackedUp(): bool;

    /**
     * @internal
     */
    public function isUvInitialized(): bool;

    /**
     * @internal
     */
    public function withUpdatedSignCount(int $newSignCount): CredentialInterface;
    // add:
    // - withUvInitialized(bool)
    // - withAttestation(AO, attCDJ)
    // - withBackupState(bool)
}
