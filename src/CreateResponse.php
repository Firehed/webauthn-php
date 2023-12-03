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
    /**
     * Note: transports are made public to simplify testing, and are not
     * considered part of any sort of public API.
     *
     * @param Enums\AuthenticatorTransport[] $transports
     */
    public function __construct(
        private Enums\PublicKeyCredentialType $type,
        private BinaryString $id,
        private Attestations\AttestationObjectInterface $ao,
        private BinaryString $clientDataJson,
        public readonly array $transports,
    ) {
    }

    public function isUserVerified(): bool
    {
        return $this->ao->getAuthenticatorData()->isUserVerified();
    }

    /**
     * @see 7.1
     * @link https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
     */
    public function verify(
        ChallengeManagerInterface $challenge,
        RelyingPartyInterface $rp,
        Enums\UserVerificationRequirement $uv = Enums\UserVerificationRequirement::Preferred,
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
        $cdjChallenge = $C['challenge'];
        $challenge = $challenge->useFromClientDataJSON($cdjChallenge);
        if ($challenge === null) {
            $this->fail('7.1.8', 'C.challenge');
        }

        $b64u = $challenge->getBinary()->toBase64Url();
        if (!hash_equals($b64u, $cdjChallenge)) {
            $this->fail('7.1.8', 'C.challenge');
        }

        // 7.1.9
        if (!$rp->matchesOrigin($C['origin'])) {
            $this->fail('7.1.9', 'C.origin');
        }

        // 7.1.10
        // TODO: topOrigin (new in lv3)

        // 7.1.11
        $hash = new BinaryString(hash('sha256', $this->clientDataJson->unwrap(), true));

        // 7.1.12
        // Happened in response parser
        $authData = $this->ao->getAuthenticatorData();

        // 7.1.13
        if (!$rp->permitsRpIdHash($authData)) {
            $this->fail('7.1.13', 'authData.rpIdHash');
        }

        // 7.1.14
        if (!$authData->isUserPresent()) {
            $this->fail('7.1.14', 'authData.isUserPresent');
        }

        // 7.1.15
        $isUserVerificationRequired = ($uv === Enums\UserVerificationRequirement::Required);
        if ($isUserVerificationRequired && !$authData->isUserVerified()) {
            $this->fail('7.1.15', 'authData.isUserVerified');
        }

        // 7.1.16
        if (!$authData->isBackupEligible() && $authData->isBackedUp()) {
            $this->fail('7.1.16', 'authData.BE=0 + BS=1');
        }

        // 7.1.17, 7.1.18
        // TODO: examine backup eligible/state for user flows and policies

        // 7.1.19
        // js options ~ publicKey.pubKeyCredParams[].alg
        // match $authData->ACD->alg (== ECDSA-SHA-256 = -7)

        // 7.1.20
        // TODO: clientExtensionResults / options.extensions

        // 7.1.21
        // Already parsed in AttestationParser::parse upstraem

        // 7.1.22
        // Verification is format-specific.
        $result = $this->ao->verify($hash);

        // 7.1.23
        // get trust anchors for format (return value from verify() above?)
        // -> format-specific metadata services?

        // 7.1.24
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

        // 7.1.25
        if ($this->id->getLength() > 1023) {
            $this->fail('7.1.25', 'credentialId too long');
        }

        // 7.1.26
        // check that credentialId is not registered to another user
        // (done in client code?)

        // 7.1.27
        // Create and store credential and associate with user. Storage to be
        // done in consuming code.
        $data = $authData->getAttestedCredentialData();
        $credential = new CredentialV2(
            type: $this->type,
            id: $this->id, // data->id?
            signCount: $authData->getSignCount(),
            coseKey: $data->coseKey,
            isUvInitialized: $authData->isUserVerified(),
            transports: $this->transports,
            isBackupEligible: $authData->isBackupEligible(),
            isBackedUp: $authData->isBackedUp(),
            attestation: [$this->ao, $this->clientDataJson],
        );

        // This is not part of the official procedure, but serves as a general
        // sanity-check around data handling.
        assert($this->id->equals($data->credentialId));

        return $credential;

        // 7.1.28
        // fail registration if attestation is "verified but is not
        // trustworthy"
    }

    private function fail(string $section, string $desc): never
    {
        throw new Errors\RegistrationError($section, $desc);
    }
}
