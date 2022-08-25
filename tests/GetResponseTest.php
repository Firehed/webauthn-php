<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\GetResponse
 */
class GetResponseTest extends \PHPUnit\Framework\TestCase
{
    // These hold the values which would be kept server-side.
    private Challenge $challenge;
    private CredentialInterface $credential;
    private RelyingParty $rp;

    // These hold the _default_ values from a sample parsed response.
    private BinaryString $id;
    private BinaryString $rawAuthenticatorData;
    private BinaryString $clientDataJson;
    private BinaryString $signature;

    public function setUp(): void
    {
        $codec = new Codecs\Credential();
        $this->credential = $codec->decode(
            'AQBAdNgcVUDDGH2BZC8No6bNvCDgn+HW36AeRHtqbX4EICbjJO6XnpTQNz1GVG/D' .
            '+Fm9w5Sj5VtCFdtcJ7QRMS0UXQAAAE2lAQIDJiABIVggi2VjhUOZ3BdYJd9cJBHh' .
            'hC+3yrxVjIlNHuak+SUYf0giWCAmEgP3PlrtjKb0XxB4Y3j6y6/QBn6ljfpcewJa' .
            'Rdv4hQAAAAA='
        );

        $this->rp = new RelyingParty('http://localhost:8888');

        $this->challenge = new Challenge(new BinaryString(
            base64_decode('kV49XeHREZYSMN8miCxRren46C7TyGM0jm9n6fS8Gmw=', true)
        ));

        $this->id = BinaryString::fromBytes([
            116, 216, 28, 85, 64, 195, 24, 125,
            129, 100, 47, 13, 163, 166, 205, 188,
            32, 224, 159, 225, 214, 223, 160, 30,
            68, 123, 106, 109, 126, 4, 32, 38,
            227, 36, 238, 151, 158, 148, 208, 55,
            61, 70, 84, 111, 195, 248, 89, 189,
            195, 148, 163, 229, 91, 66, 21, 219,
            92, 39, 180, 17, 49, 45, 20, 93,
        ]);
        $this->rawAuthenticatorData = BinaryString::fromBytes([
            73, 150, 13, 229, 136, 14, 140, 104,
            116, 52, 23, 15, 100, 118, 96, 91,
            143, 228, 174, 185, 162, 134, 50, 199,
            153, 92, 243, 186, 131, 29, 151, 99,
            1, 0, 0, 1, 23,
        ]);
        $this->clientDataJson = BinaryString::fromBytes([
            123, 34, 116, 121, 112, 101, 34, 58,
            34, 119, 101, 98, 97, 117, 116, 104,
            110, 46, 103, 101, 116, 34, 44, 34,
            99, 104, 97, 108, 108, 101, 110, 103,
            101, 34, 58, 34, 107, 86, 52, 57,
            88, 101, 72, 82, 69, 90, 89, 83,
            77, 78, 56, 109, 105, 67, 120, 82,
            114, 101, 110, 52, 54, 67, 55, 84,
            121, 71, 77, 48, 106, 109, 57, 110,
            54, 102, 83, 56, 71, 109, 119, 34,
            44, 34, 111, 114, 105, 103, 105, 110,
            34, 58, 34, 104, 116, 116, 112, 58,
            47, 47, 108, 111, 99, 97, 108, 104,
            111, 115, 116, 58, 56, 56, 56, 56,
            34, 125,
        ]);
        $this->signature = BinaryString::fromBytes([
            48, 68, 2, 32, 14, 250, 224, 129,
            7, 201, 240, 230, 116, 107, 139, 146,
            182, 75, 158, 61, 78, 36, 146, 65,
            19, 190, 77, 173, 142, 236, 221, 251,
            205, 9, 210, 36, 2, 32, 52, 79,
            190, 78, 50, 88, 32, 78, 157, 225,
            137, 105, 109, 19, 85, 10, 72, 150,
            48, 31, 150, 139, 30, 239, 98, 204,
            1, 90, 103, 114, 23, 105,
        ]);
    }

    // 7.2.11
    public function testCDJTypeMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        $cdj['type'] = 'incorrect';

        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $newCdj,
            signature: $this->signature,
        );

        $this->expectVerificationError('7.2.11');
        $response->verify($this->challenge, $this->rp, $this->credential);
    }

    // 7.2.12
    public function testCDJChallengeMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        $cdj['challenge'] = 'incorrect';

        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $newCdj,
            signature: $this->signature,
        );

        $this->expectVerificationError('7.2.12');
        $response->verify($this->challenge, $this->rp, $this->credential);
    }

    // 7.2.13
    public function testCDJOriginMismatchIsError(): void
    {
        $cdj = json_decode($this->clientDataJson->unwrap(), true, flags: JSON_THROW_ON_ERROR);
        $cdj['origin'] = 'incorrect';

        $newCdj = new BinaryString(json_encode($cdj, JSON_THROW_ON_ERROR));
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $newCdj,
            signature: $this->signature,
        );

        $this->expectVerificationError('7.2.13');
        $response->verify($this->challenge, $this->rp, $this->credential);
    }

    // 7.2.15
    public function testRelyingPartyIdMismatchIsError(): void
    {
        $rp = new RelyingParty('https://some-other-site.example.com');
        // override authData instead?
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $this->clientDataJson,
            signature: $this->signature,
        );

        $this->expectVerificationError('7.2.15');
        $response->verify($this->challenge, $rp, $this->credential);
    }

    // 7.2.16
    public function testUserNotPresentIsError(): void
    {
        // override authData
        self::markTestIncomplete();
    }

    // 7.2.17
    public function testUserVerifiedNotPresentWhenRequiredIsError(): void
    {
        // Default data is all good, but the authData has userVerified=false
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $this->clientDataJson,
            signature: $this->signature,
        );

        $this->expectVerificationError('7.2.17');
        $response->verify($this->challenge, $this->rp, $this->credential, UserVerificationRequirement::Required);
    }

    // 7.2.20
    public function testIncorrectSignatureIsError(): void
    {
        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $this->clientDataJson,
            signature: new BinaryString('incorrect'),
        );

        $this->expectVerificationError('7.2.20');
        $response->verify($this->challenge, $this->rp, $this->credential);
    }

    public function testVerifyReturnsCredentialWithUpdatedCounter(): void
    {
        // Sanity-check: this was from the initial registration which must have
        // a sign counter of zero.
        assert($this->credential->getSignCount() === 0);

        $response = new GetResponse(
            credentialId: $this->id,
            rawAuthenticatorData: $this->rawAuthenticatorData,
            clientDataJson: $this->clientDataJson,
            signature: $this->signature,
        );

        $updatedCredential = $response->verify($this->challenge, $this->rp, $this->credential);
        self::assertGreaterThan(
            0,
            $updatedCredential->getSignCount(),
            'Updated credential should have increased sign count',
        );
    }

    private function expectVerificationError(string $section): void
    {
        $this->expectException(Error\VerificationError::class);
        // TODO: how to assert on $section
    }
    /**
     * Reserved for future use
     * expected pass/fail behavior for verify when UV=0
     * (override UV here?)
     */
    public function verify(): array
    {
        return [
            'required' => [UserVerificationRequirement::Required, false],
            'preferred' => [UserVerificationRequirement::Preferred, true],
            'discouraged' => [UserVerificationRequirement::Discouraged, true],
        ];
    }
}
