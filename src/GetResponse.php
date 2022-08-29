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
    public function __construct(
        private BinaryString $credentialId,
        private BinaryString $rawAuthenticatorData,
        private BinaryString $clientDataJson,
        private BinaryString $signature,
    ) {
    }

    /**
     * @internal
     */
    public function getUsedCredentialId(): BinaryString
    {
        return $this->credentialId;
    }

    /**
     * @see 7.2
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     */
    public function verify(
        Challenge $challenge,
        RelyingParty $rp,
        CredentialInterface $credential,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
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

        // 7.2.7
        // get credential from JS credential.id
        // (index into possible credential list?)
        // $credential is this value.

        // 7.2.8
        $cData = $this->clientDataJson->unwrap();
        $authData = AuthenticatorData::parse($this->rawAuthenticatorData);
        $sig = $this->signature->unwrap();

        // 7.2.9
        $JSONtext = $cData; // already utf8

        // 7.2.10
        $C = json_decode($JSONtext, true);
        if (!is_array($C)) {
            throw new Errors\ParseError('7.2.10', 'JSON decoding returned the wrong format');
        }

        // 7.2.11
        if ($C['type'] !== 'webauthn.get') {
            $this->fail('7.2.11', 'C.type');
        }

        // 7.2.12
        $b64u = Codecs\Base64Url::encode($challenge->getUnwrappedBinary());
        if (!hash_equals($b64u, $C['challenge'])) {
            $this->fail('7.2.12', 'C.challenge');
        }

        // 7.2.13
        if (!hash_equals($rp->getOrigin(), $C['origin'])) {
            $this->fail('7.2.13', 'C.origin');
        }

        // 7.2.14
        // TODO: tokenBinding (may not exist on localhost??)

        // 7.2.15
        $knownRpIdHash = hash('sha256', $rp->getId(), true);
        if (!hash_equals($knownRpIdHash, $authData->getRpIdHash()->unwrap())) {
            $this->fail('7.2.15', 'authData.rpIdHash');
        }

        // 7.2.16
        if (!$authData->isUserPresent()) {
            $this->fail('7.2.16', 'authData.isUserPresent');
        }

        // 7.2.17
        $isUserVerificationRequired = ($uv === UserVerificationRequirement::Required);
        if ($isUserVerificationRequired && !$authData->isUserVerified()) {
            $this->fail('7.2.17', 'authData.isUserVerified');
        }

        // 7.2.18
        // TODO: clientExtensionResults / options.extensions

        // 7.2.19
        $hash = hash('sha256', $cData, true);

        // 7.2.20
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
            $this->fail('7.2.20', 'Signature verification');
        }

        // 7.2.21
        $storedSignCount = $credential->getSignCount();
        if ($authData->getSignCount() !== 0 || $storedSignCount !== 0) {
            if ($authData->getSignCount() > $storedSignCount) {
                $credential = $credential->withUpdatedSignCount($authData->getSignCount());
            } else {
                // FIXME: throw/alert for risk
            }
        }
        // 7.2.22

        // var_dump(__METHOD__, __LINE__, $authData);

        // Send back the (updated?) credential so that the sign counter can be
        // updated.
        return $credential;
    }

    private function fail(string $section, string $desc): never
    {
        throw new Errors\VerificationError($section, $desc);
    }
}
