<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ChallengeInterface
{
    /**
     * @api
     *
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
     * While this is not deprecated, it's recommended to instead use
     * getBase64Url instead as it's more consistent with WebAuthn native
     * formats.
     */
    public function getBase64(): string;

    /**
     * @api
     *
     * Same idea as getBase64() but (unsurprisingly) returns the base64url
     * format variant. This is used in newer WebAuthn APIs natively.
     */
    public function getBase64Url(): string;

    /**
     * @internal
     */
    public function getBinary(): BinaryString;
}
