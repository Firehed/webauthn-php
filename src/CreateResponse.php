<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use UnexpectedValueException;

/**
 * This is the internal representation of a PublicKeyCredential containing an
 * AuthenticatorAttestationResponse; i.e. the result of calling
 * `navigator.credentials.create()`.
 *
 * @internal
 */
class CreateResponse implements Responses\AttestationInterface
{
    public function __construct(
        private BinaryString $id,
        private Attestations\AttestationObjectInterface $ao,
        private BinaryString $clientDataJson,
    ) {
    }

    /**
     * @see 7.1
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
     */
    public function verify(
        ChallengeInterface $challenge,
        RelyingParty $rp,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface {
        // 7.1.1 - 7.1.3 are client code
        // 7.1.4 is temporarily skpped
        // 7.1.5 is done in the response parser

        // 7.1.6
        $C = json_decode($this->clientDataJson->unwrap(), true);
        if (!is_array($C)) {
            throw new Errors\ParseError('7.1.6', 'JSON decoding returned the wrong format');
        }

        // 7.1.7
        if ($C['type'] !== 'webauthn.create') {
            $this->fail('7.1.7', 'C.type');
        }

        // 7.1.8
        $b64u = Codecs\Base64Url::encode($challenge->getBinary()->unwrap());
        if (!hash_equals($b64u, $C['challenge'])) {
            $this->fail('7.1.8', 'C.challenge');
        }

        // 7.1.9
        if (!hash_equals($rp->getOrigin(), $C['origin'])) {
            $this->fail('7.1.9', 'C.origin');
        }

        // 7.1.10
        // TODO: tokenBinding (may not exist on localhost??)

        // 7.1.11
        $hash = new BinaryString(hash('sha256', $this->clientDataJson->unwrap(), true));

        // 7.1.12
        // Happened in response parser
        $authData = $this->ao->getAuthenticatorData();

        // 7.1.13
        $knownRpIdHash = hash('sha256', $rp->getId(), true);
        if (!hash_equals($knownRpIdHash, $authData->getRpIdHash()->unwrap())) {
            $this->fail('7.1.13', 'authData.rpIdHash');
        }

        // 7.1.14
        if (!$authData->isUserPresent()) {
            $this->fail('7.1.14', 'authData.isUserPresent');
        }

        // 7.1.15
        $isUserVerificationRequired = ($uv === UserVerificationRequirement::Required);
        if ($isUserVerificationRequired && !$authData->isUserVerified()) {
            $this->fail('7.1.15', 'authData.isUserVerified');
        }

        // 7.1.16
        // js options ~ publicKey.pubKeyCredParams[].alg
        // match $authData->ACD->alg (== ECDSA-SHA-256 = -7)

        // 7.1.17
        // TODO: clientExtensionResults / options.extensions

        // 7.1.18
        // Already parsed in AttestationParser::parse upstraem

        // 7.1.19
        // Verification is format-specific.
        $result = $this->ao->verify($hash);

        // 7.1.20
        // get trust anchors for format (return value from verify() above?)
        // -> format-specific metadata services?

        // 7.1.21
        // assess verification result
        //
        // In the original u2f-php lib, this was done with openssl:
        // ```php
        // $result = openssl_x509_checkpurpose(
        //   [attestation trust path cerificate],
        //   X509_PURPOSE_ANY,
        //   [list of imported trusted CAs]
        // );
        // ```
        //
        // here, it would be something like
        // ```php
        $trustworthiness = match ($result->type) {
            Attestations\AttestationType::None,
            Attestations\AttestationType::Basic => null, // check if $rp permits this?
            default => null, // openssl_x509_checkpurpose ?
        };
        // ```

        // 7.1.22
        // check that credentialId is not registered to another user
        // (done in client code?)

        // 7.1.23
        // associate credential with new user
        // done in client code
        $credential = $authData->getAttestedCredential();

        // This is not part of the official procedure, but serves as a general
        // sanity-check around data handling. It also silences an unused
        // variable warning in PHPStan :)
        assert($credential->getId()->equals($this->id));

        return $credential;

        // 7.1.24
        // fail registration if attestation is "verified but is not
        // trustworthy"
    }

    public function getChallenge(): ChallengeInterface
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true);
        assert(is_array($cdj));
        assert(array_key_exists('challenge', $cdj));
        // FIXME: real one

        return Challenge::fromClientDataJSONValue($cdj['challenge']);
    }

    private function fail(string $section, string $desc): never
    {
        throw new Errors\RegistrationError($section, $desc);
    }
}
