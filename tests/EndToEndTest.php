<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversNothing
 */
class EndToEndTest extends \PHPUnit\Framework\TestCase
{
    private RelyingPartyInterface $rp;

    public function setUp(): void
    {
        $this->rp = new SingleOriginRelyingParty('http://localhost:8888');
    }

    /**
     * @dataProvider vectors
     */
    public function testRegisterAndLogin(string $directory): void
    {
        $isUserVerified = $this->safeReadJsonFileRaw("$directory/verified.json");

        $parser = new ArrayBufferResponseParser();

        $registerInfo = $this->safeReadJsonFile("$directory/registerInfo.json");
        $registerChallenge = new Challenge(
            BinaryString::fromBase64($registerInfo['challengeB64']), // @phpstan-ignore-line
        );
        $registerRequest = $this->safeReadJsonFile("$directory/register.json");

        $attestation = $parser->parseCreateResponse($registerRequest);
        self::assertSame($isUserVerified, $attestation->isUserVerified());
        $credential = $attestation->verify($this->wrapChallenge($registerChallenge), $this->rp);

        $loginInfo = $this->safeReadJsonFile("$directory/loginInfo.json");
        $loginChallenge = new Challenge(
            BinaryString::fromBase64($loginInfo['challengeB64']), // @phpstan-ignore-line
        );
        $loginRequest = $this->safeReadJsonFile("$directory/login.json");

        $assertion = $parser->parseGetResponse($loginRequest);
        self::assertSame($isUserVerified, $assertion->isUserVerified());
        $updatedCredential = $assertion->verify(
            $this->wrapChallenge($loginChallenge),
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
        $data = $this->safeReadJsonFileRaw($path);
        assert(is_array($data));
        return $data;
    }

    private function safeReadJsonFileRaw(string $path): mixed
    {
        if (!file_exists($path)) {
            throw new \LogicException("$path is missing");
        }
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \LogicException("$path could not be read");
        }
        return json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
    }

    private function wrapChallenge(ChallengeInterface $challenge): ChallengeManagerInterface
    {
        $mock = $this->createMock(ChallengeManagerInterface::class);
        $mock->method('useFromClientDataJSON')
            ->willReturn($challenge);
        return $mock;
    }
}
