<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    Challenge,
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
    public function verify(
        Challenge $challenge,
        RelyingParty $rp,
        CredentialInterface $credential,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;
}
