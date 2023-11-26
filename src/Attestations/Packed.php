<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;
use Firehed\WebAuthn\COSE;
use UnexpectedValueException;

/**
 * @internal
 *
 * §8.2
 * @link https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
 */
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
        $signedData = new BinaryString(sprintf(
            '%s%s',
            $data->getRaw()->unwrap(),
            $clientDataHash->unwrap(),
        ));

        $acd = $data->getAttestedCredentialData();
        $alg = COSE\Algorithm::tryFrom($this->data['alg']);
        if ($alg !== $acd->coseKey->algorithm) {
            throw new \Exception('8.2/v3.a');
        }

        if (array_key_exists('x5c', $this->data)) {
            // THIS IS THEORETICAL AND NOT YET TESTED
            // $x5c = $this->data['x5c'];
            // assert(is_array($x5c) && count($x5c) >= 1);
            // $attestnCertX509 = $x5c[0];
            //
            // Convert to PEM (or not?) and run through openssl cert parsing
            // openssl_verify w/ signedData, sig, $attestnCert

            // check for extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // if present, check that it === $acd->aaguid

            // Optionally, inspect x5c and consult externally provided
            // knowledge to determine whether attStmt conveys a Basic or
            // AttCA attestation.

            // Once there are some known test vectors, this will get built out
            // for real.
            throw new UnexpectedValueException(
                'X5C trust path is not yet implemented for packed attestations'
            );
        } else {
            // Self attestation in use
            $credentialPublicKey = $acd->coseKey->getPublicKey();

            $result = openssl_verify(
                $signedData->unwrap(),
                $this->data['sig'],
                $credentialPublicKey->getPemFormatted(),
                \OPENSSL_ALGO_SHA256,
            );

            if ($result !== 1) {
                throw new \Exception('OpenSSL signature verification failed');
            }

            return new VerificationResult(AttestationType::Self);
        }
    }
}
