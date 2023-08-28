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
     * This is used to help access the challenges provided by the client, which
     * assists the case of having a global stateless challenge pool.
     *
     * @internal
     */
    public static function fromClientDataJSONValue(string $cdjChallenge): ChallengeInterface
    {
        // cdj contains a base64UrlWeb value
        // move to base64url::decode?
        $base64 = strtr($cdjChallenge, '-_', '+/');
        $bin = base64_decode($base64, strict: true);
        if ($bin === false) {
            throw new \Exception();
        }
        return new Challenge(new BinaryString($bin));
    }

    /**
     * @internal
     */
    public function getBinary(): BinaryString
    {
        return $this->wrapped;
    }

    /**
     * This produces a string that can be decoded with Javascript's `atob`
     * function. The result of that will need to be further encoded into a
     * BufferSource to be used in the `publicKey.challenge`; e.g. transformed
     * into a `Uint8Array`:
     *
     * ```php
     * header('Content-type: application/json');
     * echo json_encode($challenge->getBase64());
     * ```
     *
     * ```javascript
     * const response = await fetch(request to above endpoint)
     * const challengeB64 = await response.json()
     * const challenge = atob(challengeB64)
     * return Uint8Array.from(challenge, c => c.charCodeAt(0))
     * ```
     *
     * @api
     */
    public function getBase64(): string
    {
        return base64_encode($this->wrapped->unwrap());
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
        $bin = base64_decode($serialized['b64'], true);
        assert($bin !== false);
        $this->wrapped = new BinaryString($bin);
    }
}
