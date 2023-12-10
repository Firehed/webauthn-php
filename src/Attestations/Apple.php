<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Exception;
use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;
use OpenSSLCertificate;

class Apple implements AttestationStatementInterface
{
    private const OID = '1.2.840.113635.100.8.2';

    /**
     * @param array{
     *   x5c: string[],
     * } $data
     */
    public function __construct(
        private array $data,
    ) {
    }

    // 8.8
    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        // ¶2
        $nonceToHash = new BinaryString(
            $data->getRaw()->unwrap() . $clientDataHash->unwrap()
        );
        // ¶3
        $nonce = hash('sha256', $nonceToHash->unwrap(), binary: true);

        // ¶4 - there's a whole lot of validation and data extraction that the
        // spec glosses over.
        $certs = array_map(self::parseDer(...), $this->data['x5c']);
        assert(count($certs) >= 1);
        $credCert = array_shift($certs);
        $info = openssl_x509_parse($credCert);
        if ($info === false) {
            throw new Exception('Invalid certificate');
        }
        if (!array_key_exists('extensions', $info)) {
            throw new Exception('No extensions in credential cert');
        }
        $certExt = $info['extensions'];
        if (!array_key_exists(self::OID, $certExt)) {
            throw new Exception('Expected OID not present in cert extensions');
        }
        $nonceInCert = $certExt[self::OID];
        // This isn't clear in the spec, but the value arrives ASN.1-encoded.
        // Manually verify some length assumptions instead of doing some
        // full-on parsing.
        if (strlen($nonceInCert) !== 38) {
            throw new Exception("Malformed nonce in cert");
        }
        // 0x3024 SEQUENCE (constructed) legnth 36
        //   0xA122 Element 1, length 34
        //     0x0420 OCTET STRING length 32
        if (!str_starts_with(needle: "\x30\x24\xA1\x22\x04\x20", haystack: $nonceInCert)) {
            throw new Exception("Cert nonce has weird encoding");
        }
        // (finally, the actual verification procedure)
        $decodedNonceInCert = substr($nonceInCert, 6);
        if (!hash_equals($nonce, $decodedNonceInCert)) {
            throw new Exception('Nonce mismatch of expected value');
        }

        // ¶5
        $pubKey = openssl_pkey_get_public($credCert);
        if ($pubKey === false) {
            throw new Exception('Could not read pubkey of certificate');
        }
        $pkd = openssl_pkey_get_details($pubKey);
        if ($pkd === false) {
            throw new Exception('Could not extract public key info');
        }
        $credPK = $data->getAttestedCredentialData()->coseKey;
        $credPKPem = $credPK->getPublicKey()->getPemFormatted();
        // ¶6
        if (trim($pkd['key']) !== trim($credPKPem)) {
            throw new Exception('Credential public key does not match cert subject');
        }
        return new VerificationResult(
            AttestationType::AnonymizationCA,
            // trustPath: rest of x5c
        );
    }

    private static function parseDer(string $certificate): OpenSSLCertificate
    {
        // Convert DER to PEM format
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($certificate), 64, "\n")
            . "-----END CERTIFICATE-----";

        // Read and parse the certificate
        $certResource = openssl_x509_read($certificate);
        if ($certResource === false) {
            throw new Exception('Certiticate parsing error');
        }
        return $certResource;
    }
}
