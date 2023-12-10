<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\CreateResponse
 */
class CreateResponseTest extends \PHPUnit\Framework\TestCase
{
    // These hold the values which would be kept server-side.
    private RelyingPartyInterface $rp;
    private ChallengeManagerInterface $cm;

    // These hold the _default_ values from a sample parsed response.
    private BinaryString $id;
    private Attestations\AttestationObjectInterface $attestationObject;
    private BinaryString $clientDataJson;

    public function setUp(): void
    {
        $this->rp = new SingleOriginRelyingParty('http://localhost:8888');

        $this->id = BinaryString::fromBytes([
            236, 58, 219, 22, 123, 115, 98, 124,
            11, 0, 207, 244, 106, 41, 249, 202,
            71, 106, 58, 209, 209, 243, 172, 181,
            172, 43, 40, 230, 31, 122, 155, 134,
            233, 100, 181, 1, 244, 209, 87, 196,
            229, 209, 179, 114, 159, 228, 220, 236,
            239, 36, 27, 45, 159, 223, 209, 245,
            214, 39, 125, 27, 143, 115, 48, 36,
        ]);

        $aoData = BinaryString::fromBytes([
            163, 99, 102, 109, 116, 104, 102, 105,
            100, 111, 45, 117, 50, 102, 103, 97,
            116, 116, 83, 116, 109, 116, 162, 99,
            115, 105, 103, 88, 71, 48, 69, 2,
            32, 125, 241, 18, 179, 63, 148, 87,
            33, 101, 87, 90, 193, 184, 205, 46,
            140, 178, 227, 125, 156, 130, 101, 119,
            198, 219, 226, 228, 245, 150, 114, 202,
            185, 2, 33, 0, 231, 58, 231, 199,
            193, 59, 137, 101, 112, 10, 118, 58,
            7, 87, 103, 230, 182, 199, 58, 172,
            172, 67, 207, 172, 189, 216, 228, 194,
            202, 152, 27, 111, 99, 120, 53, 99,
            129, 89, 2, 49, 48, 130, 2, 45,
            48, 130, 1, 23, 160, 3, 2, 1,
            2, 2, 4, 5, 182, 5, 121, 48,
            11, 6, 9, 42, 134, 72, 134, 247,
            13, 1, 1, 11, 48, 46, 49, 44,
            48, 42, 6, 3, 85, 4, 3, 19,
            35, 89, 117, 98, 105, 99, 111, 32,
            85, 50, 70, 32, 82, 111, 111, 116,
            32, 67, 65, 32, 83, 101, 114, 105,
            97, 108, 32, 52, 53, 55, 50, 48,
            48, 54, 51, 49, 48, 32, 23, 13,
            49, 52, 48, 56, 48, 49, 48, 48,
            48, 48, 48, 48, 90, 24, 15, 50,
            48, 53, 48, 48, 57, 48, 52, 48,
            48, 48, 48, 48, 48, 90, 48, 40,
            49, 38, 48, 36, 6, 3, 85, 4,
            3, 12, 29, 89, 117, 98, 105, 99,
            111, 32, 85, 50, 70, 32, 69, 69,
            32, 83, 101, 114, 105, 97, 108, 32,
            57, 53, 56, 49, 53, 48, 51, 51,
            48, 89, 48, 19, 6, 7, 42, 134,
            72, 206, 61, 2, 1, 6, 8, 42,
            134, 72, 206, 61, 3, 1, 7, 3,
            66, 0, 4, 253, 184, 222, 179, 161,
            237, 112, 235, 99, 108, 6, 110, 182,
            0, 105, 150, 165, 249, 112, 252, 181,
            219, 136, 252, 59, 48, 93, 65, 229,
            150, 111, 12, 27, 84, 184, 82, 254,
            240, 160, 144, 126, 209, 127, 59, 255,
            194, 157, 77, 50, 27, 156, 248, 168,
            74, 44, 234, 160, 56, 202, 189, 53,
            213, 152, 222, 163, 38, 48, 36, 48,
            34, 6, 9, 43, 6, 1, 4, 1,
            130, 196, 10, 2, 4, 21, 49, 46,
            51, 46, 54, 46, 49, 46, 52, 46,
            49, 46, 52, 49, 52, 56, 50, 46,
            49, 46, 49, 48, 11, 6, 9, 42,
            134, 72, 134, 247, 13, 1, 1, 11,
            3, 130, 1, 1, 0, 126, 211, 251,
            108, 204, 37, 32, 19, 248, 47, 33,
            140, 42, 55, 218, 96, 49, 210, 14,
            127, 48, 129, 218, 252, 174, 177, 40,
            252, 127, 155, 35, 57, 20, 191, 182,
            77, 97, 53, 241, 124, 226, 33, 250,
            118, 79, 69, 62, 241, 39, 58, 140,
            233, 101, 149, 100, 66, 187, 47, 30,
            71, 72, 63, 115, 125, 203, 201, 139,
            88, 83, 119, 254, 245, 11, 39, 14,
            2, 137, 248, 132, 54, 241, 173, 207,
            73, 178, 98, 30, 229, 227, 2, 223,
            85, 91, 154, 183, 66, 114, 224, 105,
            249, 24, 20, 155, 61, 236, 79, 18,
            34, 139, 16, 192, 248, 141, 227, 106,
            245, 138, 116, 187, 68, 43, 133, 174,
            0, 83, 100, 189, 166, 112, 32, 88,
            252, 31, 45, 135, 155, 83, 1, 17,
            234, 96, 232, 108, 99, 241, 127, 165,
            148, 76, 200, 63, 10, 162, 105, 132,
            139, 62, 227, 136, 166, 192, 158, 107,
            5, 149, 63, 203, 184, 244, 126, 131,
            162, 126, 0, 114, 166, 60, 50, 173,
            100, 134, 78, 146, 109, 113, 18, 250,
            25, 151, 247, 131, 150, 86, 251, 179,
            43, 232, 247, 136, 157, 15, 1, 69,
            81, 154, 39, 175, 221, 142, 70, 176,
            76, 164, 41, 13, 133, 64, 182, 52,
            184, 134, 22, 30, 117, 136, 200, 98,
            153, 220, 221, 100, 53, 209, 103, 138,
            58, 111, 10, 116, 130, 156, 77, 211,
            247, 12, 53, 36, 209, 221, 241, 109,
            120, 173, 210, 27, 100, 104, 97, 117,
            116, 104, 68, 97, 116, 97, 88, 196,
            73, 150, 13, 229, 136, 14, 140, 104,
            116, 52, 23, 15, 100, 118, 96, 91,
            143, 228, 174, 185, 162, 134, 50, 199,
            153, 92, 243, 186, 131, 29, 151, 99,
            65, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 64, 236,
            58, 219, 22, 123, 115, 98, 124, 11,
            0, 207, 244, 106, 41, 249, 202, 71,
            106, 58, 209, 209, 243, 172, 181, 172,
            43, 40, 230, 31, 122, 155, 134, 233,
            100, 181, 1, 244, 209, 87, 196, 229,
            209, 179, 114, 159, 228, 220, 236, 239,
            36, 27, 45, 159, 223, 209, 245, 214,
            39, 125, 27, 143, 115, 48, 36, 165,
            1, 2, 3, 38, 32, 1, 33, 88,
            32, 76, 76, 91, 252, 118, 191, 197,
            203, 26, 81, 220, 70, 76, 103, 244,
            203, 236, 171, 119, 144, 99, 196, 84,
            9, 147, 188, 195, 151, 228, 114, 184,
            75, 34, 88, 32, 41, 100, 179, 87,
            130, 254, 107, 200, 157, 124, 49, 10,
            98, 63, 119, 233, 77, 194, 239, 205,
            218, 147, 101, 51, 204, 147, 69, 30,
            246, 195, 159, 113,
        ]);
        $this->attestationObject = new Attestations\AttestationObject($aoData);

        $this->clientDataJson = BinaryString::fromBytes([
            123, 34, 116, 121, 112, 101, 34, 58,
            34, 119, 101, 98, 97, 117, 116, 104,
            110, 46, 99, 114, 101, 97, 116, 101,
            34, 44, 34, 99, 104, 97, 108, 108,
            101, 110, 103, 101, 34, 58, 34, 75,
            71, 68, 70, 117, 105, 114, 75, 77,
            45, 50, 71, 115, 103, 80, 55, 70,
            115, 122, 110, 110, 83, 57, 78, 75,
            51, 115, 68, 57, 84, 108, 78, 70,
            69, 113, 109, 112, 118, 65, 108, 106,
            98, 119, 34, 44, 34, 111, 114, 105,
            103, 105, 110, 34, 58, 34, 104, 116,
            116, 112, 58, 47, 47, 108, 111, 99,
            97, 108, 104, 111, 115, 116, 58, 56,
            56, 56, 56, 34, 125,
        ]);

        $this->cm = new FixedChallengeManager(new Challenge(BinaryString::fromBytes([
            40, 96, 197, 186, 42, 202, 51, 237,
            134, 178, 3, 251, 22, 204, 231, 157,
            47, 77, 43, 123, 3, 245, 57, 77,
            20, 74, 166, 166, 240, 37, 141, 188,
        ])));
    }

    public function testIsUserVerified(): void
    {
        $response = $this->getDefaultResponse();
        self::assertFalse($response->isUserVerified(), 'Fixture is not verified');
    }

    // 7.1.7
    public function testCDJTypeMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($cdj));
        $cdj['type'] = 'incorrect';
        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));

        $response = new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $this->attestationObject,
            clientDataJson: $newCdj,
            transports: [],
        );

        $this->expectRegistrationError('7.1.7');
        $response->verify($this->cm, $this->rp);
    }

    public function testUsedChallengeIsError(): void
    {
        $response = $this->getDefaultResponse();

        $cred = $response->verify($this->cm, $this->rp);

        // Simulate replay. ChallengeManager no longer recognizes this one.
        $this->expectRegistrationError('7.1.8');
        $response->verify($this->cm, $this->rp);
    }

    // 7.1.8
    public function testCDJChallengeMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($cdj));
        $cdj['challenge'] = 'incorrect';
        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));

        $response = new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $this->attestationObject,
            clientDataJson: $newCdj,
            transports: [],
        );

        $this->expectRegistrationError('7.1.8');
        $response->verify($this->cm, $this->rp);
    }

    // 7.1.9
    public function testCDJOriginMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($cdj));
        $cdj['origin'] = 'incorrect';
        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));

        $response = new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $this->attestationObject,
            clientDataJson: $newCdj,
            transports: [],
        );

        $this->expectRegistrationError('7.1.0');
        $response->verify($this->cm, $this->rp);
    }

    // 7.1.13
    public function testRelyingPartyIdMismatchIsError(): void
    {
        $rp = new SingleOriginRelyingParty('https://some-other-site.example.com');
        $response = $this->getDefaultResponse();

        $this->expectRegistrationError('7.1.13');
        $response->verify($this->cm, $rp);
    }

    // 7.1.14
    public function testUserNotPresentIsError(): void
    {
        // override authData
        self::markTestIncomplete();
    }

    // 7.1.15
    public function testUserVerifiedNotPresentWhenRequiredIsError(): void
    {
        $response = $this->getDefaultResponse();

        $this->expectRegistrationError('7.1.15');
        $response->verify($this->cm, $this->rp, Enums\UserVerificationRequirement::Required);
    }

    // 7.1.16
    public function testPubKeyAlgorithmNotMatchingOptionsIsError(): void
    {
        self::markTestSkipped('Only EC2/ED256 supported at this time');
    }

    // 7.1.19
    public function testFormatSpecificVerificationOccurs(): void
    {
        // This one is a bit more complex - assert that the CreateResponse
        // actually calls the AttestationObject's verify method. It's
        // separately tested to ensure the format-specific verification process
        // occurs.
        $ao = self::createMock(Attestations\AttestationObjectInterface::class);
        // Use the default value
        $ao->method('getAuthenticatorData')
            ->willReturn($this->attestationObject->getAuthenticatorData());

        $ao->expects(self::once())
            ->method('verify')
            ->willReturnCallback(function (BinaryString $hash) {
                self::assertSame(
                    hash('sha256', $this->clientDataJson->unwrap(), true),
                    $hash->unwrap(),
                    'hash was not the sha256 hash of clientDataJson'
                );
                return new Attestations\VerificationResult(
                    Attestations\AttestationType::None,
                );
            });
        ;

        $response = new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $ao,
            clientDataJson: $this->clientDataJson,
            transports: [],
        );
        $response->verify($this->cm, $this->rp);
    }

    public function testSuccess(): void
    {
        $response = $this->getDefaultResponse();
        $cred = $response->verify($this->cm, $this->rp);

        self::assertSame(0, $cred->getSignCount());
        // Look for a specific id and public key?
    }

    public function testTransportsEndUpInCredential(): void
    {
        $response = new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $this->attestationObject,
            clientDataJson: $this->clientDataJson,
            transports: [
                Enums\AuthenticatorTransport::Usb,
                Enums\AuthenticatorTransport::Internal,
                Enums\AuthenticatorTransport::Ble,
                Enums\AuthenticatorTransport::SmartCard,
            ],
        );

        $cred = $response->verify($this->cm, $this->rp);
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Ble,
            Enums\AuthenticatorTransport::Internal,
            Enums\AuthenticatorTransport::SmartCard,
            Enums\AuthenticatorTransport::Usb,
        ], $cred->getTransports());
    }

    private function expectRegistrationError(string $section): void
    {
        $this->expectException(Errors\RegistrationError::class);
        // TODO: how to assert on $section
    }

    private function getDefaultResponse(): CreateResponse
    {
        return new CreateResponse(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: $this->id,
            ao: $this->attestationObject,
            clientDataJson: $this->clientDataJson,
            transports: [],
        );
    }
}
