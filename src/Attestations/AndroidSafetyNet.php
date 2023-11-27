<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;

class AndroidSafetyNet implements AttestationStatementInterface
{
    /**
     * @param array{
     *   ver: string,
     *   response: string,
     * } @data
     */
    public function __construct(
        private array $data,
    ) {
    }

    // 8.5
    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        // JWS parsing - TODO: grab a lib, actually verify signatures.
        [$header, $payload, $sig] = explode('.', $this->data['response']);

        $headerDecoded = BinaryString::fromBase64Url($header)->unwrap();
        $payloadDecoded = BinaryString::fromBase64Url($payload)->unwrap();

        $headerObj = json_decode($headerDecoded, true, flags: JSON_THROW_ON_ERROR);
        $payloadObj = json_decode($payloadDecoded, true, flags: JSON_THROW_ON_ERROR);
        var_dump($headerObj, $payloadObj, $sig);

        // Verify response.payload.nonce matches:
        $signed = new BinaryString($data->getRaw()->unwrap() . $clientDataHash->unwrap());
        $sigHash = hash('sha256', $signed->unwrap(), binary: true);
        $hashEnc = base64_encode($sigHash);

        if (!hash_equals(known_string: $hashEnc, user_string: $payloadObj['nonce'])) {
            throw new \Exception('Invalid signature');
        }

        // Verift that the SAfetyNet response actually came from the servie
        var_dump($hashEnc);


    }
 }
