<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversDefaultClass Firehed\WebAuthn\GetResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class GetResponseTest extends \PHPUnit\Framework\TestCase
{
    private CredentialInterface $credential;

    private RelyingParty $rp;

    private Challenge $challenge;

    public function setUp(): void
    {
        $codec = new Codecs\Credential();
        $this->credential = $codec->decode('AQBAdNgcVUDDGH2BZC8No6bNvCDgn+HW36AeRHtqbX4EICbjJO6XnpTQNz1GVG/D+Fm9w5Sj5VtCFdtcJ7QRMS0UXQAAAE2lAQIDJiABIVggi2VjhUOZ3BdYJd9cJBHhhC+3yrxVjIlNHuak+SUYf0giWCAmEgP3PlrtjKb0XxB4Y3j6y6/QBn6ljfpcewJaRdv4hQAAAAA=');

        $this->rp = new RelyingParty('http://localhost:8888');

        $this->challenge = new Challenge(new BinaryString(
            base64_decode('kV49XeHREZYSMN8miCxRren46C7TyGM0jm9n6fS8Gmw=', true)
        ));
    }

    public function testCDJTypeMismatchIsError(): void
    {
        // override CDJ
    }

    public function testCDJChallengeMismatchIsError(): void
    {
        // override CDJ
    }

    public function testCDJOriginMismatchIsError(): void
    {
        // override CDJ
    }

    public function testRelyingPartyIdMismatchIsError(): void
    {
        // override authData
    }

    public function testUserNotPresentIsError(): void
    {
        // override authData
    }

    public function testUserVerifiedNotPresentWhenRequiredIsError(): void
    {
        // (default data ok)
        // call verify with UVR::Required
    }

    public function testIncorrectSignatureIsError(): void
    {
        // override sig
    }

    public function testVerifyReturnsCredentialWithUpdatedCounter(): void
    {
        $json = <<<'JSON'
        {
            "rawId": {
                "0": 116,
                "1": 216,
                "2": 28,
                "3": 85,
                "4": 64,
                "5": 195,
                "6": 24,
                "7": 125,
                "8": 129,
                "9": 100,
                "10": 47,
                "11": 13,
                "12": 163,
                "13": 166,
                "14": 205,
                "15": 188,
                "16": 32,
                "17": 224,
                "18": 159,
                "19": 225,
                "20": 214,
                "21": 223,
                "22": 160,
                "23": 30,
                "24": 68,
                "25": 123,
                "26": 106,
                "27": 109,
                "28": 126,
                "29": 4,
                "30": 32,
                "31": 38,
                "32": 227,
                "33": 36,
                "34": 238,
                "35": 151,
                "36": 158,
                "37": 148,
                "38": 208,
                "39": 55,
                "40": 61,
                "41": 70,
                "42": 84,
                "43": 111,
                "44": 195,
                "45": 248,
                "46": 89,
                "47": 189,
                "48": 195,
                "49": 148,
                "50": 163,
                "51": 229,
                "52": 91,
                "53": 66,
                "54": 21,
                "55": 219,
                "56": 92,
                "57": 39,
                "58": 180,
                "59": 17,
                "60": 49,
                "61": 45,
                "62": 20,
                "63": 93
            },
            "type": "public-key",
            "authenticatorData": {
                "0": 73,
                "1": 150,
                "2": 13,
                "3": 229,
                "4": 136,
                "5": 14,
                "6": 140,
                "7": 104,
                "8": 116,
                "9": 52,
                "10": 23,
                "11": 15,
                "12": 100,
                "13": 118,
                "14": 96,
                "15": 91,
                "16": 143,
                "17": 228,
                "18": 174,
                "19": 185,
                "20": 162,
                "21": 134,
                "22": 50,
                "23": 199,
                "24": 153,
                "25": 92,
                "26": 243,
                "27": 186,
                "28": 131,
                "29": 29,
                "30": 151,
                "31": 99,
                "32": 1,
                "33": 0,
                "34": 0,
                "35": 1,
                "36": 23
            },
            "clientDataJSON": {
                "0": 123,
                "1": 34,
                "2": 116,
                "3": 121,
                "4": 112,
                "5": 101,
                "6": 34,
                "7": 58,
                "8": 34,
                "9": 119,
                "10": 101,
                "11": 98,
                "12": 97,
                "13": 117,
                "14": 116,
                "15": 104,
                "16": 110,
                "17": 46,
                "18": 103,
                "19": 101,
                "20": 116,
                "21": 34,
                "22": 44,
                "23": 34,
                "24": 99,
                "25": 104,
                "26": 97,
                "27": 108,
                "28": 108,
                "29": 101,
                "30": 110,
                "31": 103,
                "32": 101,
                "33": 34,
                "34": 58,
                "35": 34,
                "36": 107,
                "37": 86,
                "38": 52,
                "39": 57,
                "40": 88,
                "41": 101,
                "42": 72,
                "43": 82,
                "44": 69,
                "45": 90,
                "46": 89,
                "47": 83,
                "48": 77,
                "49": 78,
                "50": 56,
                "51": 109,
                "52": 105,
                "53": 67,
                "54": 120,
                "55": 82,
                "56": 114,
                "57": 101,
                "58": 110,
                "59": 52,
                "60": 54,
                "61": 67,
                "62": 55,
                "63": 84,
                "64": 121,
                "65": 71,
                "66": 77,
                "67": 48,
                "68": 106,
                "69": 109,
                "70": 57,
                "71": 110,
                "72": 54,
                "73": 102,
                "74": 83,
                "75": 56,
                "76": 71,
                "77": 109,
                "78": 119,
                "79": 34,
                "80": 44,
                "81": 34,
                "82": 111,
                "83": 114,
                "84": 105,
                "85": 103,
                "86": 105,
                "87": 110,
                "88": 34,
                "89": 58,
                "90": 34,
                "91": 104,
                "92": 116,
                "93": 116,
                "94": 112,
                "95": 58,
                "96": 47,
                "97": 47,
                "98": 108,
                "99": 111,
                "100": 99,
                "101": 97,
                "102": 108,
                "103": 104,
                "104": 111,
                "105": 115,
                "106": 116,
                "107": 58,
                "108": 56,
                "109": 56,
                "110": 56,
                "111": 56,
                "112": 34,
                "113": 125
            },
            "signature": {
                "0": 48,
                "1": 68,
                "2": 2,
                "3": 32,
                "4": 14,
                "5": 250,
                "6": 224,
                "7": 129,
                "8": 7,
                "9": 201,
                "10": 240,
                "11": 230,
                "12": 116,
                "13": 107,
                "14": 139,
                "15": 146,
                "16": 182,
                "17": 75,
                "18": 158,
                "19": 61,
                "20": 78,
                "21": 36,
                "22": 146,
                "23": 65,
                "24": 19,
                "25": 190,
                "26": 77,
                "27": 173,
                "28": 142,
                "29": 236,
                "30": 221,
                "31": 251,
                "32": 205,
                "33": 9,
                "34": 210,
                "35": 36,
                "36": 2,
                "37": 32,
                "38": 52,
                "39": 79,
                "40": 190,
                "41": 78,
                "42": 50,
                "43": 88,
                "44": 32,
                "45": 78,
                "46": 157,
                "47": 225,
                "48": 137,
                "49": 105,
                "50": 109,
                "51": 19,
                "52": 85,
                "53": 10,
                "54": 72,
                "55": 150,
                "56": 48,
                "57": 31,
                "58": 150,
                "59": 139,
                "60": 30,
                "61": 239,
                "62": 98,
                "63": 204,
                "64": 1,
                "65": 90,
                "66": 103,
                "67": 114,
                "68": 23,
                "69": 105
            },
            "userHandle": {}
        }
        JSON;
        $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        $parser = new ResponseParser();
        $response = $parser->parseGetResponse($data);


        // Sanity-check: this was from the initial registration which must have
        // a sign counter of zero.
        assert($this->credential->getSignCount() === 0);

        $updatedCredential = $response->verify($this->challenge, $this->rp, $this->credential);
        self::assertGreaterThan(
            0,
            $updatedCredential->getSignCount(),
            'Updated credential should have increased sign count',
        );
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
