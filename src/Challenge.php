<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * The Challenge object has limited public-facing API:
 * - Create a challenge through the `::random()` method
 * - (Un)Serialization through passing it to \serialize and \unserialize
 * - getBase64() for sending to clients for use in
 *   CredetialCreationOptions/CredentialRequestOptions
 *
 * Methods marked as @internal are not for public use. The magic methods
 * pertaining to object serialization are only to be called through the
 * serialization functions `serialize` and `unserialize`, not directly.
 *
 * @phpstan-type SerializationFormat array{
 *   b64: string,
 * }
 */
class Challenge implements ChallengeInterface
{
    /**
     * @internal
     */
    public function __construct(
        private BinaryString $wrapped,
    ) {
    }

    /**
     * @api
     */
    public static function random(): Challenge
    {
        return new Challenge(new BinaryString(random_bytes(32)));
    }

    /**
     * @internal
     */
    public function getBinary(): BinaryString
    {
        return $this->wrapped;
    }

    public function getBase64(): string
    {
        return base64_encode($this->wrapped->unwrap());
    }

    public function getBase64Url(): string
    {
        return $this->wrapped->toBase64Url();
    }

    /**
     * @return SerializationFormat
     */
    public function __serialize(): array
    {
        return ['b64' => $this->getBase64()];
    }

    /**
     * @param SerializationFormat $serialized
     */
    public function __unserialize(array $serialized): void
    {
        $this->wrapped = BinaryString::fromBase64($serialized['b64']);
    }
}
