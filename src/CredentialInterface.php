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
     * @api
     *
     * Returns an encoded version of the credential's id guaranteed to return
     * no binary characters.
     */
    public function getStorageId(): string;

    /**
     * @internal
     */
    public function getId(): BinaryString;

    /**
     * @internal
     *
     * Retreives the COSE key in raw CBOR format
     */
    public function getCoseCbor(): BinaryString;

    /**
     * @internal
     */
    public function getSignCount(): int;

    /**
     * @internal
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface;

    public function isBackupEligible(): bool;
    public function isBackedUp(): bool;
    public function isUvInitialized(): bool;
    /** @return Enums\AuthenticatorTransport[] */
    public function getTransports(): array;

    public function getAttestationObject(): ?Attestations\AttestationObjectInterface;
    public function getAttestationClientDataJson(): ?BinaryString;


    /**
     * @internal
     */
    public function withUpdatedSignCount(int $newSignCount): CredentialInterface;
    // add:
    // - withUvInitialized(bool)
    // - withAttestationObject(AO)
    // - withBackupState(bool)
}
