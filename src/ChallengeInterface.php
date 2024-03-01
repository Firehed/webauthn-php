<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DateTimeImmutable;

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

    /**
     * If non-null, indicates when the challenge should be considered expired.
     * This should be used in conjunction with request generation and align
     * with the `timeout` used by `pkOptions`. Be aware that browsers may
     * override the specified value; the current W3C recommendation (lv3) is
     * between 5 and 10 minutes (300-600 seconds).
     *
     * At present, this is intended as a convenience for storage mechanisms and
     * expected to be enforced by _ChallengeInterface_ implemetions, not the RP
     * server and associated internals.
     */
    public function getExpiration(): ?DateTimeImmutable;
}
