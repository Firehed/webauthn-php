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
     * ```javascript
     * const credential = await navigator.credentials.create(...)
     * const wireFormat = {
     *  rawId: new Uint8Array(credential.rawId),
     *  type: credential.type,
     *  attestationObject: new Uint8Array(credential.response.attestationObject),
     *  clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
     * }
     * ```
     * @param array{
     *   rawId: int[],
     *   type: string,
     *   attestationObject: int[],
     *   clientDataJSON: int[],
     * } $response
     */
    public function parseCreateResponse(array $response): CreateResponse
    {
        if ($response['type'] !== 'public-key') {
            throw new \UnexpectedValueException();
        }
        return new CreateResponse(
            id: self::byteArrayToBinaryString($response['rawId']),
            ao: Attestations\AttestationObject::fromCbor(self::byteArrayToBinaryString($response['attestationObject'])),
            clientDataJson: self::byteArrayToBinaryString($response['clientDataJSON']),
        );
    }

    /**
     * Parses the JSON wire format from navigator.credentials.get
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
     * @param array{
     *   rawId: int[],
     *   type: string,
     *   authenticatorData: int[],
     *   clientDataJSON: int[],
     *   signature: int[],
     * } $response
     */
    public function parseGetResponse(array $response): GetResponse
    {
        if ($response['type'] !== 'public-key') {
            throw new \UnexpectedValueException();
        }

        // print_r($response);
        // if userHandle is provided, feed to the response to be read by app
        // and have key handles looked up for verify??

        return new GetResponse(
            credentialId: self::byteArrayToBinaryString($response['rawId']),
            rawAuthenticatorData: self::byteArrayToBinaryString($response['authenticatorData']),
            clientDataJson: self::byteArrayToBinaryString($response['clientDataJSON']),
            signature: self::byteArrayToBinaryString($response['signature']),
        );
    }

    /**
     * @param int[] $bytes
     */
    private static function byteArrayToBinaryString(array $bytes): BinaryString
    {
        return new BinaryString(implode('', array_map('chr', $bytes)));
    }
}
