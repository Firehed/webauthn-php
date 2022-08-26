<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Translates the library-official over-the-wire data formats into the
 * necessary data structures for subsequent authentication procedures.
 *
 * Observe that most of the Javascript API responses are returned as an
 * ArrayBuffer, which does not have a default JSON encoding. As such, they are
 * sent over the wire as an array of ordinal bytes; i.e. an ArrayBufer
 * containing "ABC" would render as `[65, 66, 67]` (or `{"0": 65, "1": 66, "2":
 * 67}`).
 *
 * This parser expects a specific wire format, documented as a JS example in
 * each method's docblock. That format will be converted into an internal
 * format for subsequent registration/verification procedures.
 *
 * @api
 */
class ResponseParser
{
    /**
     * Parses the JSON wire format from navigator.credentials.create
     *
     * ```javascript
     * const credential = await navigator.credentials.create(...)
     * const wireFormat = {
     *  rawId: new Uint8Array(credential.rawId),
     *  type: credential.type,
     *  attestationObject: new Uint8Array(credential.response.attestationObject),
     *  clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
     * }
     * ```
     *
     * This will arrive as the following shape:
     *
     * array{
     *   rawId: int[],
     *   type: string,
     *   attestationObject: int[],
     *   clientDataJSON: int[],
     * }
     *
     * $response is left untyped since it performs additional checking from
     * untrusted user data.
     *
     * @param mixed[] $response
     */
    public function parseCreateResponse(array $response): Responses\AttestationInterface
    {
        if (!array_key_exists('type', $response) || $response['type'] !== 'public-key') {
            throw new Error\ParseError('7.1.2', 'response.type');
        }
        if (!array_key_exists('rawId', $response) || !is_array($response['rawId'])) {
            throw new Error\ParseError('7.1.2', 'response.rawId');
        }
        if (!array_key_exists('attestationObject', $response) || !is_array($response['attestationObject'])) {
            throw new Error\ParseError('7.1.2', 'response.attestationObject');
        }
        if (!array_key_exists('clientDataJSON', $response) || !is_array($response['clientDataJSON'])) {
            throw new Error\ParseError('7.1.2', 'response.clientDataJSON');
        }
        return new CreateResponse(
            id: BinaryString::fromBytes($response['rawId']),
            ao: Attestations\AttestationObject::fromCbor(BinaryString::fromBytes($response['attestationObject'])),
            clientDataJson: BinaryString::fromBytes($response['clientDataJSON']),
        );
    }

    /**
     * Parses the JSON wire format from navigator.credentials.get
     *
     * ```javascript
     * const credential = await navigator.credentials.get(...)
     * const wireFormat = {
     *  rawId: new Uint8Array(credential.rawId),
     *  type: credential.type,
     *  authenticatorData: new Uint8Array(credential.response.authenticatorData),
     *  clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
     *  signature: new Uint8Array(credential.response.signature),
     *  userHandle: new Uint8Array(credential.response.userHandle),
     * }
     * ```
     *
     * This will arrive as the following shape:
     *
     * array{
     *   rawId: int[],
     *   type: string,
     *   authenticatorData: int[],
     *   clientDataJSON: int[],
     *   signature: int[],
     * }
     *
     * $response is left untyped since it performs additional checking from
     * untrusted user data.
     *
     * @param mixed[] $response
     */
    public function parseGetResponse(array $response): Responses\AssertionInterface
    {
        if (!array_key_exists('type', $response) || $response['type'] !== 'public-key') {
            throw new Error\ParseError('7.2.2', 'response.type');
        }
        if (!array_key_exists('rawId', $response) || !is_array($response['rawId'])) {
            throw new Error\ParseError('7.2.2', 'response.rawId');
        }
        if (!array_key_exists('authenticatorData', $response) || !is_array($response['authenticatorData'])) {
            throw new Error\ParseError('7.2.2', 'response.authenticatorData');
        }
        if (!array_key_exists('clientDataJSON', $response) || !is_array($response['clientDataJSON'])) {
            throw new Error\ParseError('7.2.2', 'response.clientDataJSON');
        }
        if (!array_key_exists('signature', $response) || !is_array($response['signature'])) {
            throw new Error\ParseError('7.2.2', 'response.signature');
        }

        // userHandle provides the user.id from registration
        // var_dump(BinaryString::fromBytes($response['userHandle'])->unwrap());
        // if userHandle is provided, feed to the response to be read by app
        // and have key handles looked up for verify??

        return new GetResponse(
            credentialId: BinaryString::fromBytes($response['rawId']),
            rawAuthenticatorData: BinaryString::fromBytes($response['authenticatorData']),
            clientDataJson: BinaryString::fromBytes($response['clientDataJSON']),
            signature: BinaryString::fromBytes($response['signature']),
        );
    }
}
