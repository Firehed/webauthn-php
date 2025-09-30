<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use LogicException;

#[CoversClass(JsonResponseParser::class)]
class JsonResponseParserTest extends TestCase
{
    /**
     * Test the happy case for various known-good responses.
     */
    #[DataProvider('goodVectors')]
    public function testParseCreateResponse(string $directory): void
    {
        $parser = new JsonResponseParser();
        $registerResponse = self::safeReadJsonFile("$directory/register.json");
        $attestation = $parser->parseCreateResponse($registerResponse);

        self::assertInstanceOf(CreateResponse::class, $attestation);
    }

    /**
     * @param mixed[] $response
     */
    #[DataProvider('badCreateResponses')]
    public function testParseCreateResponseInputValidation(array $response): void
    {
        $parser = new JsonResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseCreateResponse($response);
    }

    public function testParseCreateResponseWithInvalidTransports(): void
    {
        $response = self::readFixture('safari-passkey-polyfill/register.json');
        $response['response']['transports'] = ['invalid', 'usb']; // @phpstan-ignore-line

        $parser = new JsonResponseParser();
        $parsed = $parser->parseCreateResponse($response);
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Usb,
        ], $parsed->transports); // @phpstan-ignore-line (interface/impl cheat)
    }

    /**
     * @param mixed[] $response
     */
    #[DataProvider('badGetResponses')]
    public function testParseGetResponseInputValidation(array $response): void
    {
        $parser = new JsonResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseGetResponse($response);
    }

    public function testParseGetResponseHandlesFilledUserHandle(): void
    {
        $parser = new JsonResponseParser();
        $response = self::readFixture('safari-passkey-polyfill/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertSame('usr_686mCXhr7Hm7wc49CPccMhpf', $assertion->getUserHandle());
    }

    public function testParseGetResponseHandlesEmptyUserHandle(): void
    {
        $parser = new JsonResponseParser();
        $response = self::readFixture('fido-u2f-polyfill/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertNull($assertion->getUserHandle());
    }

    public function testParseGetResponseHandlesNullUserHandle(): void
    {
        $parser = new JsonResponseParser();
        $response = self::readFixture('fido-u2f-native/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertNull($assertion->getUserHandle());
    }

    /**
     * @return array<mixed>[]
     */
    public static function badCreateResponses(): array
    {
        $makeVector = function (array $overrides): array {
            $response = self::readFixture('fido-u2f-polyfill/register.json');
            foreach ($overrides as $key => $value) {
                if ($value === null) {
                    unset($response[$key]);
                } elseif (is_array($value)) {
                    // Yes, this is awful. But it's a fixed depth and works.
                    foreach ($value as $key2 => $value2) {
                        if ($value2 === null) {
                            unset($response[$key][$key2]);
                        } else {
                            $response[$key][$key2] = $value2;
                        }
                    }
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
            'no response' => $makeVector(['response' => null]),
            'no attestationObject' => $makeVector(['response' => ['attestationObject' => null]]),
            'invalid attestationObject' => $makeVector(['response' => ['attestationObject' => 'not base 64']]),
            'no clientDataJSON' => $makeVector(['response' => ['clientDataJSON' => null]]),
            'invalid clientDataJSON' => $makeVector(['response' => ['clientDataJSON' => 'not base 64']]),
            'no transports' => $makeVector(['response' => ['transports' => null]]),
        ];
    }

    /**
     * @return array<mixed>[]
     */
    public static function badGetResponses(): array
    {
        $makeVector = function (array $overrides): array {
            $response = self::readFixture('fido-u2f-polyfill/login.json');
            foreach ($overrides as $key => $value) {
                if ($value === null) {
                    unset($response[$key]);
                } elseif (is_array($value)) {
                    // Yes, this is awful. But it's a fixed depth and works.
                    foreach ($value as $key2 => $value2) {
                        if ($value2 === null) {
                            unset($response[$key][$key2]);
                        } else {
                            $response[$key][$key2] = $value2;
                        }
                    }
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
            'no response' => $makeVector(['response' => null]),
            'no authenticatorData' => $makeVector(['response' => ['authenticatorData' => null]]),
            // invalid authenticatorData
            'no clientDataJSON' => $makeVector(['response' => ['clientDataJSON' => null]]),
            // invalid clientDataJSON
            'no signature' => $makeVector(['response' => ['signature' => null]]),
            'invalid signature' => $makeVector(['response' => ['signature' => 'not base 64']]),
        ];
    }

    /**
     * Test the happy case for various known-good responses.
     */
    #[DataProvider('goodVectors')]
    public function testParseGetResponse(string $directory): void
    {
        $parser = new JsonResponseParser();
        $loginResponse = self::safeReadJsonFile("$directory/login.json");
        $assertion = $parser->parseGetResponse($loginResponse);

        self::assertInstanceOf(GetResponse::class, $assertion);
    }

    /**
     * @return array{string}[]
     */
    public static function goodVectors(): array
    {
        $paths = glob(__DIR__ . '/fixtures/toJSON/*');
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
    private static function safeReadJsonFile(string $path): array
    {
        if (!file_exists($path)) {
            throw new LogicException("$path is missing");
        }
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new LogicException("$path could not be read");
        }
        $data = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($data));
        return $data;
    }

    /**
     * @return mixed[]
     */
    private static function readFixture(string $relativePath): array
    {
        return self::safeReadJsonFile(__DIR__ . '/fixtures/toJSON/' . $relativePath);
    }
}
