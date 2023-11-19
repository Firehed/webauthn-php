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
     *   extensions?: AuthenticationExtensionsClientInputsJSON
     * }
     */
    public function createDataForCreationOptions(): array
    {
        $challenge = $this->challengeManager->createChallenge();
        $data = [
            'rp' => [
                'name' => $fixme,
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
            // Future: support the other numerous flags
        ];
        return $data;
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
    public function createDataForRequestOptions(
        ?CredentialContainer $credentials = null,
    ): array {
        $challenge = $this->challengeManager->createChallenge();

        $data = [
            'challenge' => $challenge->getBinary()->toBase64Url(),
        ];
        if ($credentials === null) {
            // No allowCredentials, this is assumed to be a conditional
            // mediation request where the user is not yet known.
        } else {
            $data['timeout'] = 300_000; // 5 min
            // Future scope/concept:
            // $data['allowCredentials'] = array_map(fn ($credential) => [
            //     'id' => $credential->getBase64UrlId(),
            //     'type' => $credential->getType(),
            //     transports: previously registered transports if known
            // ], $credentials);
        }

        return $data;
    }
}

require 'vendor/autoload.php';
session_start();
$je = new JsonEmitter(new SessionChallengeManager());
echo json_encode($je->createDataForCreationOptions(), JSON_PRETTY_PRINT);
echo json_encode($je->createDataForRequestOptions(), JSON_PRETTY_PRINT);
