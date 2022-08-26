<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversNothing
 */
class EndToEndTest extends \PHPUnit\Framework\TestCase
{
    private RelyingParty $rp;

    public function setUp(): void
    {
        $this->rp = new RelyingParty('http://localhost:8888');
    }

    /**
     * @dataProvider vectors
     */
    public function testRegisterAndLogin(string $directory): void
    {
        $parser = new ResponseParser();

        $registerInfo = $this->safeReadJsonFile("$directory/registerInfo.json");
        $registerChallenge = new Challenge(
            BinaryString::fromBase64($registerInfo['challengeB64']), // @phpstan-ignore-line
        );
        $registerRequest = $this->safeReadJsonFile("$directory/register.json");

        $attestation = $parser->parseCreateResponse($registerRequest); // @phpstan-ignore-line
        $credential = $attestation->verify($registerChallenge, $this->rp);

        $loginInfo = $this->safeReadJsonFile("$directory/loginInfo.json");
        $loginChallenge = new Challenge(
            BinaryString::fromBase64($loginInfo['challengeB64']), // @phpstan-ignore-line
        );
        $loginRequest = $this->safeReadJsonFile("$directory/login.json");

        $assertion = $parser->parseGetResponse($loginRequest); // @phpstan-ignore-line
        $updatedCredential = $assertion->verify(
            $loginChallenge,
            $this->rp,
            $credential,
        );

        self::assertTrue(
            $credential->getId()->equals($updatedCredential->getId()),
            'Updated credential id changed',
        );

        self::assertSame(
            $credential->getPublicKey()->getPemFormatted(),
            $updatedCredential->getPublicKey()->getPemFormatted(),
            'Public key changed',
        );
    }

    /**
     * @return array{string}[]
     */
    public function vectors(): array
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
