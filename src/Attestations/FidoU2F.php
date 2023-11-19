<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;

/**
 * @internal
 *
 * @see 8.6
 * @link https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
 */
class FidoU2F implements AttestationStatementInterface
{
    /**
     * @param array{
     *   sig: string,
     *   x5c: string[],
     * } $data
     * FIXME: $data contains binary :/
     */
    public function __construct(
        private array $data,
    ) {
    }

    // 8.6
    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        // 8.6.v.1 already done
        // // check data['sig'] is set?
        // 8.6.v.2
        assert(count($this->data['x5c']) === 1);
        $attCert = new Certificate(new BinaryString($this->data['x5c'][0]));

        $certificatePublicKey = openssl_pkey_get_public($attCert->getPemFormatted());
        assert($certificatePublicKey !== false);
        $info = openssl_pkey_get_details($certificatePublicKey);
        assert($info !== false);
        if ($info['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new \Exception('Certificate PubKey is not Elliptic Curve');
        }
        // OID for P-156 curve
        // http://oid-info.com/get/1.2.840.10045.3.1.7
        // See also EllipticCurve
        if ($info['ec']['curve_oid'] !== '1.2.840.10045.3.1.7') {
            throw new \Exception('Certificate PubKey is not Elliptic Curve');
        }

        // 8.6.v.3
        $rpIdHash = $data->getRpIdHash();
        $attestedCredentialData = $data->getAttestedCredentialData();
        $credentialId = $attestedCredentialData->credentialId;
        $credentialPublicKey = $attestedCredentialData->coseKey->getPublicKey();
        assert($credentialPublicKey instanceof EllipticCurve);

        // 8.6.v.4
        // The specific indexing is handled within the data structure
        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $credentialPublicKey->getXCoordinate()->unwrap(),
            $credentialPublicKey->getYCoordinate()->unwrap(),
        );


        // 8.6.v.5
        $verificationData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            $rpIdHash->unwrap(),
            $clientDataHash->unwrap(),
            $credentialId->unwrap(),
            $publicKeyU2F,
        );

        // 8.6.v.6
        $sig = $this->data['sig'];

        $result = openssl_verify(
            $verificationData,
            $sig,
            $attCert->getPemFormatted(),
            \OPENSSL_ALGO_SHA256,
        );

        if ($result !== 1) {
            throw new \Exception('OpenSSL signature verification failed');
        }
        // var_dump(__METHOD__, $result);
        //
        $pem = $attCert->getPemFormatted();
        // $crt = openssl_x509_read($pem);
        // var_dump($pem);

        // 8.6.v.7
        // examine this->data[x5c] and dig into attestation
        // figure out if Basic or AttCA (??) defined in 6.5.3
        // FIXME: should not be hardcoded!
        $type = AttestationType::Basic;
        // "or uncertainty" ^^ what's the right thing to do here?

        // 8.6.v.8
        return new VerificationResult($type, [$attCert]);
    }
}
