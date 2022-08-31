<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
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
     * @api
     */
    public function verify(
        ChallengeInterface $challenge,
        RelyingParty $rp,
        CredentialInterface $credential,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;
}
