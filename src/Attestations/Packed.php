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
    private const AAGUID_EXTENSION_OID = '1.3.6.1.4.1.45724.1.1.4';
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
            $attCert = new Certificate(new BinaryString($this->data['x5c'][0]));
            $certPubKey = openssl_pkey_get_public($attCert->getPemFormatted());
            if ($certPubKey === false) {
                throw new \Exception('Public key not readable');
            }

            $result = openssl_verify(
                $signedData->unwrap(),
                $this->data['sig'],
                $certPubKey,
                \OPENSSL_ALGO_SHA256,
            );

            // Verify that `sig` is ...
            if ($result !== 1) {
                throw new \Exception('OpenSSL signature verification failed');
            }

            // echo ($attCert->getPemFormatted());
            // print_r($certPubKey);

            $parsed = openssl_x509_parse($attCert->getPemFormatted());
            if ($parsed === false) {
                throw new \Exception('Attestation certificate could not be parsed');
            }

            // Enforce att. cert requirements: §8.2.1
            // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements
            //
            // Note: as of writing, $parsed's format is EXPLICITLY
            // undocumented, so this needs to play a little loose right now.

            // version == 3 (asn1 integer 2)
            if (!array_key_exists('version', $parsed) || $parsed['version'] !== 2) {
                throw new \Exception('Attestation certificate invalid version');
            }
            if (!array_key_exists('subject', $parsed)) {
                throw new \Exception('Attestation certificate missing subject');
            }
            $subject = $parsed['subject'];
            assert(strlen($subject['C']) === 2);
            // O: vendor name
            assert($subject['OU'] === 'Authenticator Attestation');
            // CN: string of vendor's choosing
            assert($parsed['extensions']['basicConstraints'] === 'CA:FALSE');

            // var_dump($parsed);
            // var_dump(openssl_pkey_get_details($certPubKey));



            if (array_key_exists(self::AAGUID_EXTENSION_OID, $parsed['extensions'] ?? [])) {
                // This is in ASN.1 notation. Skip full parsing in favor of
                // a direct read.
                $oid = $parsed['extensions'][self::AAGUID_EXTENSION_OID];
                // echo bin2hex($oid);
                if (strlen($oid) !== 18) {
                    throw new \Exception('idofido-gen-ce-aaguid extension is malformed');
                }
                // OCTET STRING, length 0x10 (==16)
                if (!str_starts_with(haystack: $oid, needle: "\x04\x10")) {
                    throw new \Exception('idofido-gen-ce-aaguid extension is malformed');
                }
                $certAaguid = substr($oid, 2);
                assert(strlen($certAaguid) === 16);

                if (!hash_equals($acd->aaguid->unwrap(), $certAaguid)) {
                    throw new \Exception('aaguid in extension mismatch');
                }
            }

            // TODO: "Optionally, inspect x5c and consult externally provided
            // knowledge to determine whether attStmt conveys a Basic or AttCA
            // attestation."
            return new VerificationResult(AttestationType::Uncertain, [
                $attCert,
            ]);
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
