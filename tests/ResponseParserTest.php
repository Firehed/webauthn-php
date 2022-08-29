<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\ResponseParser
 */
class ResponseParserTest extends \PHPUnit\Framework\TestCase
{
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
