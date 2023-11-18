<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
    ChallengeManagerInterface,
    CredentialContainer,
    CredentialInterface,
    RelyingPartyInterface,
    Enums\UserVerificationRequirement,
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
     * This is used to find the used credential in the credential container. It
     * is not used to determine what user is authenticating, and MUST NOT be
     * used in an attempt to do so.
     *
     * @internal
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
    public function isUserVerified(): bool;

    /**
     * @api
     */
    public function verify(
        ChallengeManagerInterface $challenge,
        RelyingPartyInterface $rp,
        CredentialContainer | CredentialInterface $credential,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;
}
