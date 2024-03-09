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
     * } $data
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
        // var_dump($headerObj, $payloadObj, $sig);

        // Verify response.payload.nonce matches:
        $signed = new BinaryString($data->getRaw()->unwrap() . $clientDataHash->unwrap());
        $sigHash = hash('sha256', $signed->unwrap(), binary: true);
        $hashEnc = base64_encode($sigHash);

        if (!hash_equals(known_string: $hashEnc, user_string: $payloadObj['nonce'])) {
            throw new \Exception('Invalid signature');
        }

        // Verify that the SafetyNet response actually came from the service
        // https://developer.android.com/privacy-and-security/safetynet/attestation#verify-attestation-response
        // var_dump($hashEnc);
        // Extract the SSL certificate chain from the JWS message.
        foreach ($headerObj['x5c'] as $cert) {
            $crt = self::parseDer($cert);
            $info = openssl_x509_parse($crt);
            // print_r($info);
        }
// Validate the SSL certificate chain and use SSL hostname matching to verify that the leaf certificate was issued to the hostname attest.android.com.
// Use the certificate to verify the signature of the JWS message.
// Check the data of the JWS message to make sure it matches the data within your original request. In particular, make sure that the timestamp has been validated and that the nonce, package name, and hashes of the app's signing certificate(s) match the expected values.


    }

    private static function parseDer(string $base64)
    {
        $certificate = base64_decode($base64);

        // Convert DER to PEM format
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($certificate), 64, "\n")
            . "-----END CERTIFICATE-----";

        // Read and parse the certificate
        $certResource = openssl_x509_read($certificate);

        return ($certResource);
    }
}
