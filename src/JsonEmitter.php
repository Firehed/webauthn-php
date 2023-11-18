<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class JsonEmitter
{
    /**
     * @link https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON
     */
    public function createDataForCreationOptions(): array
    {
        $challenge = Challenge::random();
        $timeout = 10_000;
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
                ['type' => Enums\PublicKeyCredentialType::PublicKey, 'alg' => Enums\CoseAlgorithmIdentifier::ES256],
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
     */
    public function createDataForRequestOptions(): array
    {
        // TODO: if we have a user (credential container?), fill out
        // allowCredentials and set timeout to some reasonable value. If not,
        // assume it's a conditional mediation request, leave allowCredentials
        // empty, and disable the timeout.
        $challenge = Challenge::random();
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
