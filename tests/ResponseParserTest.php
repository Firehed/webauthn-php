<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\ResponseParser
 */
class ResponseParserTest extends \PHPUnit\Framework\TestCase
{
    public function testPRRJ(): void
    {
        $j = <<<'JSON'
        {
            "type":"public-key",
            "id":"XJ6Kap3UyS7bCRQwJpgJgV2gEBps1v7GnRCkN7t6MwOEDTz8YJdsDJWsQPKtX-Brt7DvNGPnK5lp0BicCQXSgw",
            "rawId":"XJ6Kap3UyS7bCRQwJpgJgV2gEBps1v7GnRCkN7t6MwOEDTz8YJdsDJWsQPKtX-Brt7DvNGPnK5lp0BicCQXSgw",
            "authenticatorAttachment":"cross-platform",
            "response":{
                "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRXJ5VHdIYnFYbEhid3o4elBtN0Fyb2xIT1lJYUJ1eGZaTFVKd0pIajV1WSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9",
                "attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQFyeimqd1Mku2wkUMCaYCYFdoBAabNb-xp0QpDe7ejMDhA08_GCXbAyVrEDyrV_ga7ew7zRj5yuZadAYnAkF0oOlAQIDJiABIVggnKywkljFLYA9zHL4kJm85-XgZCTV2GTmpFDIwCunKkUiWCDmnE7Dz-TKL_nKK5PudCIUxl9z5bEdNoqsGQnLP0RWsg",
                "transports":["usb"]
            },
            "clientExtensionResults":{
            }
        }
        JSON;
    }

    /**
     * Test the happy case for various known-good responses.
     *
     * @dataProvider goodVectors
     */
    public function testParseCreateResponse(string $directory): void
    {
        $parser = new ResponseParser();
        $registerResponse = $this->safeReadJsonFile("$directory/register.json");
        $attestation = $parser->parseCreateResponse($registerResponse);

        self::assertInstanceOf(CreateResponse::class, $attestation);
    }

    /**
     * @dataProvider badCreateResponses
     * @param mixed[] $response
     */
    public function testParseCreateResponseInputValidation(array $response): void
    {
        $parser = new ResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseCreateResponse($response);
    }

    /**
     * @dataProvider badGetResponses
     * @param mixed[] $response
     */
    public function testParseGetResponseInputValidation(array $response): void
    {
        $parser = new ResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseGetResponse($response);
    }

    public function testParseGetResponseHandlesEmptyUserHandle(): void
    {
        $parser = new ResponseParser();
        $response = $this->safeReadJsonFile(__DIR__ . '/fixtures/fido-u2f/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertNull($assertion->getUserHandle());
    }

    public function testParseGetResponseHandlesProvidedUserHandle(): void
    {
        $parser = new ResponseParser();
        $response = $this->safeReadJsonFile(__DIR__ . '/fixtures/touchid/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertSame('443945aa-8acc-4b84-f05f-ec8ef86e7c5d', $assertion->getUserHandle());
    }

    /**
     * @return array<mixed>[]
     */
    public function badCreateResponses(): array
    {
        $makeVector = function (array $overrides): array {
            $response = $this->safeReadJsonFile(__DIR__ . '/fixtures/fido-u2f/register.json');
            foreach ($overrides as $key => $value) {
                if ($value === null) {
                    unset($response[$key]);
                } else {
                    $response[$key] = $value;
                }
            }

            return [$response];
        };

        return [
            'no type' => $makeVector(['type' => null]),
            'invalid type' => $makeVector(['type' => 'publickey']),
            'no rawId' => $makeVector(['rawId' => null]),
            'invalid rawId' => $makeVector(['rawId' => 'some value']),
            'no attestationObject' => $makeVector(['attestationObject' => null]),
            // invalid attestationObject
            'no clientDataJSON' => $makeVector(['clientDataJSON' => null]),
            // invalid clientDataJSON
        ];
    }

    /**
     * @return array<mixed>[]
     */
    public function badGetResponses(): array
    {
        $makeVector = function (array $overrides): array {
            $response = $this->safeReadJsonFile(__DIR__ . '/fixtures/fido-u2f/login.json');
            foreach ($overrides as $key => $value) {
                if ($value === null) {
                    unset($response[$key]);
                } else {
                    $response[$key] = $value;
                }
            }

            return [$response];
        };

        return [
            'no type' => $makeVector(['type' => null]),
            'invalid type' => $makeVector(['type' => 'publickey']),
            'no rawId' => $makeVector(['rawId' => null]),
            'invalid rawId' => $makeVector(['rawId' => 'some value']),
            'no authenticatorData' => $makeVector(['authenticatorData' => null]),
            // invalid authenticatorData
            'no clientDataJSON' => $makeVector(['clientDataJSON' => null]),
            // invalid clientDataJSON
            'no signature' => $makeVector(['signature' => null]),
            'invalid signature' => $makeVector(['signature' => 'sig']),
            'no userHandle' => $makeVector(['userHandle' => null]),
        ];
    }

    /**
     * Test the happy case for various known-good responses.
     *
     * @dataProvider goodVectors
     */
    public function testParseGetResponse(string $directory): void
    {
        $parser = new ResponseParser();
        $loginResponse = $this->safeReadJsonFile("$directory/login.json");
        $assertion = $parser->parseGetResponse($loginResponse);

        self::assertInstanceOf(GetResponse::class, $assertion);
    }

    /**
     * @return array{string}[]
     */
    public function goodVectors(): array
    {
        $paths = glob(__DIR__ . '/fixtures/*');
        assert($paths !== false);
        $vectors = [];
        foreach ($paths as $path) {
            $name = pathinfo($path, PATHINFO_FILENAME);
            $vectors[$name] = [$path];
        }
        return $vectors;
    }

    /**
     * @return mixed[]
     */
    private function safeReadJsonFile(string $path): array
    {
        if (!file_exists($path)) {
            throw new \LogicException("$path is missing");
        }
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \LogicException("$path could not be read");
        }
        $data = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($data));
        return $data;
    }
}
