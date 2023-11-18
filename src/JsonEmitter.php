<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @phpstan-type Base64UrlString string
 *
 * @phpstan-type PublicKeyCredentialUserEntityJson array{
 *   id: Base64UrlString,
 *   name: string,
 *   displayName: string,
 * }
 *
 * @phpstan-type PublicKeyCredentialRpEntity array{
 *   name: string,
 *   id?: string,
 * }
 *
 * @phpstan-type PublicKeyCredentialParameters array{
 *   type: Enums\PublicKeyCredentialType,
 *   alg: COSE\Algorithm,
 * }
 *
 * @phpstan-type PublicKeyCredentialDescriptorJson array{
 *   id: Base64UrlString,
 *   type: Enums\PublicKeyCredentialType,
 *   transports?: Enums\AuthenticatorTransport[],
 * }
 *
 * @phpstan-type AuthenticatorSelectionCriteria array{
 *   authenticatorAttachment?: Enums\AuthenticatorAttachment,
 *   residentKey?: Enums\ResidentKeyRequirement,
 *   requireResidentKey?: bool,
 *   userVerification?: Enums\UserVerificationRequirement,
 * }
 *
 * @phpstan-type AuthenticationExtensionsClientInputsJSON array{}
 */
class JsonEmitter
{
    public function __construct(
        private ChallengeManagerInterface $challengeManager,
    ) {
    }

    /**
     * @link https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON
     *
     * @return array{
     *   rp: PublicKeyCredentialRpEntity,
     *   user: PublicKeyCredentialUserEntityJson,
     *   challenge: Base64UrlString,
     *   pubKeyCredParams: PublicKeyCredentialParameters[],
     *   timeout?: int,
     *   excludeCredentials?: PublicKeyCredentialDescriptorJson[],
     *   authenticatorSelection?: AuthenticatorSelectionCriteria,
     *   hints?: Enums\PublicKeyCredentialHints[],
     *   attestation?: Enums\AttestationConveyancePreference,
     *   attestationFormats?: Attestations\Format[],
     *   extensions: AuthenticationExtensionsClientInputsJSON
     * }
     */
    public function createDataForCreationOptions(): array
    {
        $challenge = $this->challengeManager->createChallenge();
        $timeout = 300_000; // TODO: match to challenge TTL
        $d = [
            'rp' => [
                'id' => $fixme,
            ],
            'user' => [
                'id' => $fixme_base64url,
                'name' => $fixme,
                'displayName' => $fixme,
            ],
            'challenge' => $challenge->getBinary()->toBase64Url(),

            'pubKeyCredParams' => [
                ['type' => Enums\PublicKeyCredentialType::PublicKey, 'alg' => COSE\Algorithm::EcdsaSha256],
            ],
            'timeout' => $timeout,
            'excludeCredentials' => [
                // array of { type: Enums\PublicKeyCredentialType, id: base64u,
                // transports?: Enums\AuthenticatorTransport[] }
            ],
            'authenticatorSelection' => [
                'authenticatorAttachment' => '',

                'residentKey' => '',
                'requireResidentKey' => false,
                'userVerification' => 'preferred',
            ],
            'hints' => [], // Enums\PublicKeyCredentialHints[]
            'attestation' => Enums\AttestationConveyancePreference::None,
            'attestationFormats' => [
                // Attestations\Format[],
            ],
            'extensions' => [
            ],
        ];

        return array_filter($d);
    }

    /**
     * @link https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON
     *
     * @return array{
     *   challenge: Base64UrlString,
     *   timeout?: int,
     *   rpId?: string,
     *   allowCredentials?: PublicKeyCredentialDescriptorJson[],
     *   userVerification?: Enums\UserVerificationRequirement,
     *   hints?: Enums\PublicKeyCredentialHints[],
     *   attestation?: Enums\AttestationConveyancePreference,
     *   attestationFormats?: Attestations\Format,
     *   extensions?: AuthenticationExtensionsClientInputsJSON,
     * }
     */
    public function createDataForRequestOptions(): array
    {
        // TODO: if we have a user (credential container?), fill out
        // allowCredentials and set timeout to some reasonable value. If not,
        // assume it's a conditional mediation request, leave allowCredentials
        // empty, and disable the timeout.

        $challenge = $this->challengeManager->createChallenge();
        $timeout = 30_000;
        $d = [
            'challenge' => $challenge->getBinary()->toBase64Url(),
            'timeout' => $timeout,
            'rpId' => $fixme,
            'allowCredentials' => [
                // same format as excludeCredentials above
            ],
            'userVerification' => Enums\UserVerificationRequirement::Preferred,
            'hints' => [], // Enums\PublicKeyCredentialHints[]
            'attestation' => Enums\AttestationConveyancePreference::None,
            'attestationFormats' => [
                // sorted, most preferred first
                // Attestations/Format[] (move to enums?)
            ],
            'extensions' => [
            ],
        ];
        return array_filter($d);
    }
}

require 'vendor/autoload.php';
$je = new JsonEmitter();
echo json_encode($je->createDataForCreationOptions(), JSON_PRETTY_PRINT);
echo json_encode($je->createDataForRequestOptions(), JSON_PRETTY_PRINT);
