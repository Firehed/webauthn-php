<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
    CredentialContainer,
    CredentialInterface,
    RelyingParty,
    UserVerificationRequirement,
};

/**
 * The internal format associated with the response of
 * `navigator.credentials.get()`, to be verified in client code.
 *
 * @api
 */
interface AssertionInterface
{
    /**
      *@internal
      */
    public function getUsedCredentialId(): BinaryString;

    /**
     * Returns the userHandle associated with the credential. This will be the
     * value set during credential creation in the
     * `PublicKeyCredentialCreationOptions.user.id` field. While applications
     * can put any value they want here, it is RECOMMENDED to store a user id
     * or equivalent.
     *
     * The value may not be binary-safe depending on how your client code set
     * up the value.
     *
     * This will be null if the authenticator doesn't support user handles. U2F
     * authenticators, at least, do not support user handles.
     *
     * @api
     */
    public function getUserHandle(): ?string;

    /**
     * @api
     */
    public function verify(
        ChallengeInterface $challenge,
        RelyingParty $rp,
        CredentialContainer | CredentialInterface $credential,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;
}
