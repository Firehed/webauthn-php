<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;

class Apple implements AttestationStatementInterface
{
    private const OID = '1.2.840.113635.100.8.2';

    /**
     * @param array{
     *   x5c: string[],
     * } @data
     */
    public function __construct(
        private array $data,
    ) {
    }

    // 8.8
    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        $nonceToHash = new BinaryString(
            $data->getRaw()->unwrap() . $clientDataHash->unwrap()
        );
        $rawNonce = hash('sha256', $nonceToHash->unwrap(), binary: true);
        $nonce = new BinaryString($rawNonce);

        $certs = array_map(self::parseDer(...), $this->data['x5c']);
        $credCert = array_shift($certs);
        // var_dump($certs);
        // $info = array_map(openssl_x509_parse(...), $certs);
        $info = openssl_x509_parse($credCert);
        $certExt = $info['extensions'];
        assert(array_key_exists(self::OID, $certExt));
        $certNonce = new BinaryString($certExt[self::OID]);
        // var_dump($nonce);
        // var_dump($certNonce);

        // 3024a1220420
        // 3024 SEQUENCE legnth 36
        //   a122 set(..) legnth 34 ?
        //     0420 OCTECT STRING length 32
        // ok, this ain't right
        $len = $certNonce->getLength();
        assert($len === 38);
        // 6, 32 = (oid stuff) (actual nonce)
        $overage = $len - (256/8); // sha output
        $leading = $certNonce->read($overage);
        $real = $certNonce->getRemaining();
        $leadingBS = new BinaryString($leading);
        $realBS = new BinaryString($real);
        // var_dump($leadingBS, $realBS);
        // var_dump($leadingBS->unwrap());



        if ($realBS->equals($nonce)) {
            // this matches
            // var_dump("OK!");
        } else {
            throw new \Exception('no');
        }
        // print_r($info);

        $pubKey = openssl_pkey_get_public($credCert);
        // var_dump($pubKey);g
        $pkd = openssl_pkey_get_details($pubKey);
        // var_dump($pkd);
        // probably a better way
        $credPK = $data->getAttestedCredentialData()->coseKey;
        $credPKPem = $credPK->getPublicKey()->getPemFormatted();
        // var_dump($credPKPem);
        if (trim($pkd['key']) === trim($credPKPem)) {
            return new VerificationResult(
                AttestationType::AnonymizationCA,
                // trustPath: rest of x5c
            );
        } else {
            // fail
        }

    }

    private static function parseDer(string $certificate)
    {
        // Convert DER to PEM format
        $certificate = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($certificate), 64, "\n")
            . "-----END CERTIFICATE-----";

        // Read and parse the certificate
        $certResource = openssl_x509_read($certificate);

        return ($certResource);
    }
}
