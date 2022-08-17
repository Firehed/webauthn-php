<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\AuthenticatorData;

class FidoU2F implements AttestationStatementInterface
{
    public function __construct(
        private array $data,
    ) {
    }

    // 8.6
    public function verify(AuthenticatorData $data, string $clientDataHash)
    {
        // 8.6.v.1 already done
        // // check data['sig'] is set?
        // 8.6.v.2
        assert(count($this->data['x5c']) === 1);
        $attCert = new Certificate($this->data['x5c'][0]);
        // TODO: Do all PEM decoding, blah blah
        // >  Let *certificate public key* be the public key conveyed by
        // > *attCert*. If *certificate public key* is not an Elliptic Curve
        // > (EC) public key over the P-256 curve, terminate this algorithm and
        // > return an appropriate error.
        // var_dump($this, $attCert->getPemFormatted());

        // 8.6.v.3
        $rpIdHash = $data->getRpIdHash();
        $attestedCredentialData = $data->getAttestedCredentialData();
        $credentialId = $attestedCredentialData['credentialId'];
        $credentialPublicKey = $attestedCredentialData['credentialPublicKey'];

        // 8.6.v.4
        // isset & strlen===32
        assert(isset($credentialPublicKey[-2]));
        assert(isset($credentialPublicKey[-3]));
        $publicKeyU2F = sprintf(
            '%s%s%s',
            "\x04",
            $credentialPublicKey[-2],
            $credentialPublicKey[-3]
        );


        // 8.6.v.5
        $verificationData = sprintf(
            '%s%s%s%s%s',
            "\x00",
            $rpIdHash,
            $clientDataHash,
            $credentialId,
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

        // 8.6.v.7
        // examine x5c and dig into attestation

        // 8.6.v.8
        // return attestation?
    }
}
