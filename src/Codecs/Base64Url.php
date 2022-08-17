<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

/**
 * @internal
 *
 * @see RFC 4648
 * @link https://www.rfc-editor.org/rfc/rfc4648
 *
 * This is a small dependency for the credential registration and assertion
 * verification processes, as they rely on this format shift for challenge
 * handling.
 */
class Base64Url
{
    public static function encode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
