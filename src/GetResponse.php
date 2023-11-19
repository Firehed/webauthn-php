<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use UnexpectedValueException;

/**
 * This is the internal representation of a PublicKeyCredential containing an
 * AuthenticatorAssertionResponse; i.e. the result of calling
 * `navigator.credentials.get()`.
 *
 * @internal
 */
class GetResponse implements Responses\AssertionInterface
{
    private AuthenticatorData $authData;

    public function __construct(
        private BinaryString $credentialId,
        private BinaryString $rawAuthenticatorData,
        private BinaryString $clientDataJson,
        private BinaryString $signature,
        private ?BinaryString $userHandle,
    ) {
        $this->authData = AuthenticatorData::parse($this->rawAuthenticatorData);
    }

    public function getUserHandle(): ?string
    {
        return $this->userHandle?->unwrap();
    }

    /**
     * @internal
     */
    public function getUsedCredentialId(): BinaryString
    {
        return $this->credentialId;
    }

    public function isUserVerified(): bool
    {
        return $this->authData->isUserVerified();
    }

    /**
     * @see 7.2
     * @link https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
     */
    public function verify(
        ChallengeManagerInterface $challenge,
        RelyingPartyInterface $rp,
        CredentialContainer | CredentialInterface $credential,
        Enums\UserVerificationRequirement $uv = Enums\UserVerificationRequirement::Preferred,
    ): CredentialInterface {
        // 7.2.1-7.2.4 are done in client side js & the ResponseParser

        // 7.2.5
        // if allowCredentials != [], assert this.id in allowCredetials

        // 7.2.6
        // id the auth'd user & verify this.id is in their credentials
        // if user came from existing data (session/cookie/etc),
        //   a) verify that the user owns the passed credential
        //   b) if this.userHandle is set, check for a match
        // if not (e.g. passkeys ~ medication:conditional)
        //   a) verify that this.userHandle is present & matches owner
        //
        // upstream implication:
        // - try to load user by userHandle
        // - get their credentials & perform existing matching procedure

        // lv3 messed up some paragraph indexing and went straight from 6 to 9;
        // the numbers are implied from past versions and context
        // @link https://github.com/w3c/webauthn/issues/1913
        // 7.2.7
        // get credential from JS credential.id
        // (index into possible credential list?)
        // $credential is this value.
        if ($credential instanceof CredentialContainer) {
            $credential = $credential->findCredentialUsedByResponse($this);
            if ($credential === null) {
                $this->fail('7.2.7', 'Credential not found in container');
            }
        }
        // 7.2.8 would be reading and using userHandle, done upstream

        // 7.2.9
        $cData = $this->clientDataJson->unwrap();
        $authData = $this->authData;
        $sig = $this->signature->unwrap();

        // 7.2.10
        $JSONtext = $cData; // already utf8

        // 7.2.11
        $C = json_decode($JSONtext, true);
        if (!is_array($C)) {
            throw new Errors\ParseError('7.2.10', 'JSON decoding returned the wrong format');
        }

        // 7.2.12
        if ($C['type'] !== 'webauthn.get') {
            $this->fail('7.2.11', 'C.type');
        }

        // 7.2.13
        $cdjChallenge = $C['challenge'];
        $challenge = $challenge->useFromClientDataJSON($cdjChallenge);
        if ($challenge === null) {
            $this->fail('7.2.12', 'C.challenge');
        }

        $b64u = $challenge->getBinary()->toBase64Url();
        if (!hash_equals($b64u, $cdjChallenge)) {
            $this->fail('7.2.12', 'C.challenge');
        }

        // 7.2.14
        if (!$rp->matchesOrigin($C['origin'])) {
            $this->fail('7.2.13', 'C.origin');
        }

        // 7.2.15: look for and verify topOrigin (new in lv3, replaced
        //   tokenbinding)

        // 7.2.16
        if (!$rp->permitsRpIdHash($authData)) {
            $this->fail('7.2.15', 'authData.rpIdHash');
        }

        // 7.2.17
        if (!$authData->isUserPresent()) {
            $this->fail('7.2.16', 'authData.isUserPresent');
        }

        // 7.2.18
        $isUserVerificationRequired = ($uv === Enums\UserVerificationRequirement::Required);
        if ($isUserVerificationRequired && !$authData->isUserVerified()) {
            $this->fail('7.2.17', 'authData.isUserVerified');
        }

        // 7.2.19
        if (!$authData->isBackupEligible() && $authData->isBackedUp()) {
            $this->fail('7.2.19', 'authData.BE=0 + BS=1');
        }

        // 7.2.20:
        // TODO: if policy requires it...
        //
        // if credential->isBackupEligible, verify $authData->isBackupEligible
        // if (!credential->isBackupEligible) verify !$authData->isBackupEligible

        // 7.2.21
        // TODO: clientExtensionResults / options.extensions

        // 7.2.22
        $hash = hash('sha256', $cData, true);

        // 7.2.23
        $credentialPublicKey = $credential->getPublicKey();

        // Spec note: the signature is over the concatenation of the authData
        // and the hash of clientDataJSON. Due to the above checks (relying
        // party id, challenge, origin, etc) contained within those data, this
        // sig check ensures a login attempt for *this site* with the known
        // server-generated challenge has been signed by a key already registed
        // to the user.
        $verificationData = sprintf(
            '%s%s',
            $this->rawAuthenticatorData->unwrap(),
            $hash,
        );
        $result = openssl_verify(
            $verificationData,
            $sig,
            $credentialPublicKey->getPemFormatted(),
            \OPENSSL_ALGO_SHA256,
        );
        if ($result !== 1) {
            $this->fail('7.2.23', 'Signature verification');
        }

        // 7.2.24
        $storedSignCount = $credential->getSignCount();
        if ($authData->getSignCount() !== 0 || $storedSignCount !== 0) {
            if ($authData->getSignCount() > $storedSignCount) {
                $credential = $credential->withUpdatedSignCount($authData->getSignCount());
            } else {
                // FIXME: throw/alert for risk
            }
        }

        // 7.2.25
        // if attestationObject is present and RP wants to verify, do more or
        // less the same thing as 7.1.22
        // 1) verify authData.AT
        // 2) match AO.publicKey and AO.credentialId match credential data
        // 3, 4) parse AO.fmt and verify
        // 5) get trust anchors

        // 7.2.26
        // - update sign count (above)
        // - update backup state
        // - if !credential.uvInitialized, update it to authData.UV
        // - if AO present, update credential.AO + CDJ

        // Send back the (updated?) credential so that the sign counter can be
        // updated.
        return $credential;
    }

    private function fail(string $section, string $desc): never
    {
        throw new Errors\VerificationError($section, $desc);
    }
}
