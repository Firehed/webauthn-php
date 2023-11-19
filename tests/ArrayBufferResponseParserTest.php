<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\ArrayBufferResponseParser
 */
class ArrayBufferResponseParserTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test the happy case for various known-good responses.
     *
     * @dataProvider goodVectors
     */
    public function testParseCreateResponse(string $directory): void
    {
        $parser = new ArrayBufferResponseParser();
        $registerResponse = $this->safeReadJsonFile("$directory/register.json");
        $attestation = $parser->parseCreateResponse($registerResponse);

        self::assertInstanceOf(CreateResponse::class, $attestation);
    }

    public function testParseCreateResponseWithTransports(): void
    {
        $response = $this->readFixture('touchid/register.json');
        $response['transports'] = ['internal', 'hybrid'];

        $parser = new ArrayBufferResponseParser();
        $parsed = $parser->parseCreateResponse($response);
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Hybrid,
            Enums\AuthenticatorTransport::Internal,
        ], $parsed->transports); // @phpstan-ignore-line (interface/impl cheat)
    }

    public function testParseCreateResponseWithInvalidTransports(): void
    {
        $response = $this->readFixture('touchid/register.json');
        $response['transports'] = ['invalid', 'usb'];

        $parser = new ArrayBufferResponseParser();
        $parsed = $parser->parseCreateResponse($response);
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Usb,
        ], $parsed->transports); // @phpstan-ignore-line (interface/impl cheat)
    }

    /**
     * @dataProvider badCreateResponses
     * @param mixed[] $response
     */
    public function testParseCreateResponseInputValidation(array $response): void
    {
        $parser = new ArrayBufferResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseCreateResponse($response);
    }

    /**
     * @dataProvider badGetResponses
     * @param mixed[] $response
     */
    public function testParseGetResponseInputValidation(array $response): void
    {
        $parser = new ArrayBufferResponseParser();
        $this->expectException(Errors\ParseError::class);
        $parser->parseGetResponse($response);
    }

    public function testParseGetResponseHandlesEmptyUserHandle(): void
    {
        $parser = new ArrayBufferResponseParser();
        $response = $this->readFixture('fido-u2f/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertNull($assertion->getUserHandle());
    }

    public function testParseGetResponseHandlesProvidedUserHandle(): void
    {
        $parser = new ArrayBufferResponseParser();
        $response = $this->readFixture('touchid/login.json');
        $assertion = $parser->parseGetResponse($response);

        self::assertSame('443945aa-8acc-4b84-f05f-ec8ef86e7c5d', $assertion->getUserHandle());
    }

    /**
     * @return array<mixed>[]
     */
    public function badCreateResponses(): array
    {
        $makeVector = function (array $overrides): array {
            $response = $this->readFixture('fido-u2f/register.json');
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
            $response = $this->readFixture('fido-u2f/login.json');
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
        $parser = new ArrayBufferResponseParser();
        $loginResponse = $this->safeReadJsonFile("$directory/login.json");
        $assertion = $parser->parseGetResponse($loginResponse);

        self::assertInstanceOf(GetResponse::class, $assertion);
    }

    /**
     * @return array{string}[]
     */
    public function goodVectors(): array
    {
        $paths = glob(__DIR__ . '/fixtures/ArrayBuffer/*');
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

    /**
     * @return mixed[]
     */
    private function readFixture(string $relativePath): array
    {
        return $this->safeReadJsonFile(__DIR__ . '/fixtures/ArrayBuffer/' . $relativePath);
    }
}
