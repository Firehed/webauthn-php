<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;


class Packed implements AttestationStatementInterface
{
    /**
     * @param array{
     *   alg: int,
     *   sig: string,
     *   x5c?: string[],
     * } $data
     */
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        // Need AD raw version?
        $signedData = new BinaryString($data->getRaw()->unwrap(), $clientDataHash->unwrap());

        assert($this->data['alg'] === -7);

        if (array_key_exists('x5c', $this->data)) {
            // Check attstn
            d(count($this->data['x5c']));
            foreach ($this->data['x5c'] as $chainEntry) {
            }
        } else {
            // Self attestation in use
            // d('self attest');
            $attestedCredentialData = $data->getAttestedCredentialData();
            $credentialPublicKey = $attestedCredentialData->coseKey->getPublicKey();

            var_dump(
                $signedData,
                new BinaryString($this->data['sig']),
                $credentialPublicKey->getPemFormatted(),
            );

            $result = openssl_verify(
                $signedData->unwrap(),
                $this->data['sig'],
                // $attCert->getPemFormatted(),
                $credentialPublicKey->getPemFormatted(),
                \OPENSSL_ALGO_SHA256,
            );
            var_dump($result);
        }

    }
}
