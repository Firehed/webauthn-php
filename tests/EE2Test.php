<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Firehed\WebAuthn\EE2
 */
class EE2Test extends TestCase
{
    public static function vectors(): array
    {
        $dirs = glob('tests/ee/*');
        $out = [];
        foreach ($dirs as $dir) {
            $out[$dir] = [$dir];
        }
        return $out;
    }

    /**
     * @dataProvider vectors
     */
    public function testReg(string $dir): void
    {
        $rpInfo = self::read($dir, 'rp');
        $rp = new SingleOriginRelyingParty($rpInfo['origin']);

        $cd = self::read($dir, 'reg-req');
        $challengeManager = $this->makeChallengeManager($cd);

        $jrp = new JsonResponseParser();

        $cr = self::read($dir, 'reg-res');
        $createResponse = $jrp->parseCreateResponse($cr);

        $cred = $createResponse->verify(
            $challengeManager,
            $rp,
        );


        var_dump($cd, $cr, $createResponse);

    }

    private static function read($dir, $file): array
    {
        $file = sprintf('%s/%s.json', $dir, $file);
        $data = file_get_contents($file);
        return json_decode($data, true, flags: JSON_THROW_ON_ERROR);
    }

    private function makeChallengeManager($req): ChallengeManagerInterface
    {
        return new class implements ChallengeManagerInterface
        {

            public function createChallenge(): ChallengeInterface
            {
                throw new \BadMethodCallException();
            }

            public function useFromClientDataJSON(string $base64Url): ChallengeInterface
            {
                return new FixedChallenge($base64Url);
            }
        };
    }
}

class FixedChallenge implements ChallengeInterface
{
    public function __construct(private string $b64u)
    {
    }
    public function getBinary(): BinaryString
    {
        return BinaryString::fromBase64Url($this->b64u);
    }
    public function getBase64(): string
    {
        throw new \Exception('not here');
    }
}
