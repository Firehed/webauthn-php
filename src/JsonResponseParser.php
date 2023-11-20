<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use UnexpectedValueException;

use function array_key_exists;
use function is_array;
use function is_string;

/**
 * Parses and decodes the native `PublicKeyCredential.toJSON()` formats into the
 * necessary data structures for subsequent authentication procedures. When
 * using this decoder, the original value provided by the javascript API should
 * be passed in after parsing the raw JSON (using `associative: true`)
 *
 * @api
 */
class JsonResponseParser implements ResponseParserInterface
{
    /**
     * Parses the JSON wire format from navigator.credentials.create
     *
     * This should arrive as the following shape:
     *
     * array{
     *   id: Base64UrlString,
     *   rawId: Base64UrlString,
     *   response: array{
     *     clientDataJSON: Base64UrlString,
     *     authenticatorData: Base64UrlString,
     *     transports: string[],
     *     publicKey?: Base64UrlString,
     *     publicKeyAlgorithm: int,
     *     attestationObject: Base64UrlString,
     *   },
     *   authenticatorAttachment?: string,
     *   clientExtensionResults: array{
     *   },
     *   type: string,
     * }
     *
     * $data is left untyped since it performs additional checking from
     * untrusted user data.
     *
     * @param mixed[] $data
     */
    public function parseCreateResponse(array $data): Responses\AttestationInterface
    {
        // Note: the recommended polyfill library (as of writing) excludes some
        // of the fields defined as required by the W3C spec. Fortunately,
        // they're not needed.
        if (!array_key_exists('type', $data) || $data['type'] !== 'public-key') {
            throw new Errors\ParseError('7.1.2', 'type');
        }
        if (!array_key_exists('rawId', $data) || !is_string($data['rawId'])) {
            throw new Errors\ParseError('7.1.2', 'rawId');
        }
        if (!array_key_exists('response', $data) || !is_array($data['response'])) {
            throw new Errors\ParseError('7.1.2', 'response');
        }
        $response = $data['response'];
        if (!array_key_exists('attestationObject', $response) || !is_string($response['attestationObject'])) {
            throw new Errors\ParseError('7.1.2', 'response.attestationObject');
        }
        if (!array_key_exists('clientDataJSON', $response) || !is_string($response['clientDataJSON'])) {
            throw new Errors\ParseError('7.1.2', 'response.clientDataJSON');
        }
        if (!array_key_exists('transports', $response) || !is_array($response['transports'])) {
            throw new Errors\ParseError('7.1.2', 'response.transports');
        }
        // "client platforms MUST ignore unknown values" -> tryFrom+filter
        $transports = array_filter(array_map(Enums\AuthenticatorTransport::tryFrom(...), $response['transports']));

        return new CreateResponse(
            type: Enums\PublicKeyCredentialType::from($data['type']),
            id: self::parse($data['rawId'], '7.1.2', 'rawId'),
            ao: new Attestations\AttestationObject(
                self::parse($response['attestationObject'], '7.1.2', 'response.attestationObject'),
            ),
            clientDataJson: self::parse($response['clientDataJSON'], '7.1.2', 'response.clientDataJSON'),
            transports: $transports,
        );
    }

    /**
     * This will arrive as the following shape:
     *
     * array{
     *   id: Base64UrlString,
     *   rawId: Base64UrlString,
     *   response: array{
     *     clientDataJSON: Base64UrlString,
     *     authenticatorData: Base64UrlString,
     *     signature: Base64UrlString,
     *     userHandle?: Base64UrlString,
     *     attestationObject?: Base64UrlString,
     *   },
     *   authenticatorAttachment?: string,
     *   clientExtensionResults: array{},
     *   type: string,
     * }
     *
     * $data is left untyped since it performs additional checking from
     * untrusted user data.
     *
     * @param mixed[] $data
     */
    public function parseGetResponse(array $data): Responses\AssertionInterface
    {
        if (!array_key_exists('type', $data) || $data['type'] !== 'public-key') {
            throw new Errors\ParseError('7.2.2', 'type');
        }
        if (!array_key_exists('rawId', $data) || !is_string($data['rawId'])) {
            throw new Errors\ParseError('7.2.2', 'rawId');
        }
        if (!array_key_exists('response', $data) || !is_array($data['response'])) {
            throw new Errors\ParseError('7.1.2', 'response');
        }
        $response = $data['response'];
        if (!array_key_exists('authenticatorData', $response) || !is_string($response['authenticatorData'])) {
            throw new Errors\ParseError('7.2.2', 'response.authenticatorData');
        }
        if (!array_key_exists('clientDataJSON', $response) || !is_string($response['clientDataJSON'])) {
            throw new Errors\ParseError('7.2.2', 'response.clientDataJSON');
        }
        if (!array_key_exists('signature', $response) || !is_string($response['signature'])) {
            throw new Errors\ParseError('7.2.2', 'response.signature');
        }

        return new GetResponse(
            credentialId: self::parse($data['rawId'], '7.2.2', 'rawId'),
            rawAuthenticatorData: self::parse($response['authenticatorData'], '7.2.2', 'response.authenticatorData'),
            clientDataJson: self::parse($response['clientDataJSON'], '7.2.2', 'response.clientDataJSON'),
            signature: self::parse($response['signature'], '7.2.2', 'response.signature'),
            userHandle: array_key_exists('userHandle', $response) && $response['userHandle'] !== ''
                ? self::parse($response['userHandle'], '7.2.2', 'response.userHandle')
                : null,
        );
    }

    private static function parse(string $data, string $failSection, string $failMessage): BinaryString
    {
        try {
            return BinaryString::fromBase64Url($data);
        } catch (UnexpectedValueException) {
            throw new Errors\ParseError($failSection, $failMessage);
        }
    }
}
