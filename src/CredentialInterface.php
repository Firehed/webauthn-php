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
     * TODO: better name?
     */
    public function getSafeId(): string;

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
}
