<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Translates the library-official over-the-wire data formats into the
 * necessary data structures for subsequent authentication procedures.
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
            id: new BinaryString(self::byteArrayToBinaryString($response['rawId'])),
            ao: AttestationParser::parse(self::byteArrayToBinaryString($response['attestationObject'])),
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
        var_dump("userHandle:", self::byteArrayToBinaryString($response['userHandle']));
        // if userHandle is provided, feed to the response to be read by app
        // and have key handles looked up for verify??

        return new GetResponse(
            id: new BinaryString(self::byteArrayToBinaryString($response['rawId'])),
            rawAuthenticatorData: new BinaryString(self::byteArrayToBinaryString($response['authenticatorData'])),
            clientDataJson: self::byteArrayToBinaryString($response['clientDataJSON']),
            signature: new BinaryString(self::byteArrayToBinaryString($response['signature'])),
        );
    }

    /**
     * @param int[] $bytes
     */
    private static function byteArrayToBinaryString(array $bytes): string
    {
        return implode('', array_map('chr', $bytes));
    }
}
