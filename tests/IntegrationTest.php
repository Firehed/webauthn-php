<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Firehed\WebAuthn\EE2
 *
 * TODO: merge EndToEndTest into here
 */
class IntegrationTest extends TestCase
{
    /**
     * @return array<string, array{string}>
     */
    public static function vectors(): array
    {
        $dirs = glob('tests/integration/*');
        assert($dirs !== false);
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


        var_dump($cred);

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
                return new TestUtilities\FixedChallenge($base64Url);
            }
        };
    }
}
