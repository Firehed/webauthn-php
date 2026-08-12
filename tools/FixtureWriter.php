<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Tools;

use Firehed\WebAuthn\BinaryString;
use UnexpectedValueException;

use function array_key_exists;
use function array_map;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Renders a Vector as the files IntegrationTest consumes. Every decision about
 * the on-disk shape lives here.
 *
 * The spec publishes each value as hex; the wire format the response parsers
 * expect is base64url, so that is the only transformation applied.
 */
class FixtureWriter
{
    /**
     * @return array<string, string> file name => contents
     */
    public function render(Vector $vector): array
    {
        $reg = $vector->registration;
        $credentialId = self::encode($reg['credential_id']);

        $files = [
            // No spec counterpart; supplies what the harness needs but neither
            // response carries.
            'metadata.json' => [
                'id' => $credentialId,
                'origin' => self::origin($reg['clientDataJSON']),
            ],
            'reg-req.json' => [
                'publicKey' => [
                    'challenge' => self::encode($reg['challenge']),
                ],
            ],
            'reg-res.json' => [
                'id' => $credentialId,
                'rawId' => $credentialId,
                'response' => [
                    'clientDataJSON' => self::encode($reg['clientDataJSON']),
                    'attestationObject' => self::encode($reg['attestationObject']),
                    // JsonResponseParser rejects the response outright if this
                    // is absent, and the vectors carry no transport hints.
                    'transports' => [],
                ],
                'type' => 'public-key',
            ],
        ];

        $auth = $vector->authentication;
        if ($auth !== null) {
            $files['auth-req.json'] = [
                'publicKey' => [
                    'challenge' => self::encode($auth['challenge']),
                ],
            ];
            $files['auth-res.json'] = [
                'rawId' => $credentialId,
                'response' => [
                    'authenticatorData' => self::encode($auth['authenticatorData']),
                    'signature' => self::encode($auth['signature']),
                    'clientDataJSON' => self::encode($auth['clientDataJSON']),
                ],
                'type' => 'public-key',
            ];
        }

        return array_map(self::toJson(...), $files);
    }

    private static function encode(string $hex): string
    {
        return BinaryString::fromHex($hex)->toBase64Url();
    }

    private static function origin(string $clientDataJsonHex): string
    {
        $decoded = json_decode(BinaryString::fromHex($clientDataJsonHex)->unwrap(), true);
        if (!is_array($decoded) || !array_key_exists('origin', $decoded) || !is_string($decoded['origin'])) {
            throw new UnexpectedValueException('clientDataJSON does not contain a usable origin');
        }
        return $decoded['origin'];
    }

    /**
     * @param mixed[] $data
     */
    private static function toJson(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }
}
