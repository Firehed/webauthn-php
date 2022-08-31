<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\Challenge
 */
class ChallengeTest extends \PHPUnit\Framework\TestCase
{
    use ChallengeInterfaceTestTrait;

    protected function getChallenge(): ChallengeInterface
    {
        return Challenge::random();
    }

    /**
     * This covers the specific scenario of a challenge being unserialized
     * (e.g. from a Session) that was generated from an older version of this
     * library. This helps ensure compatibility across versions and reduces the
     * risk of a point release breaking any active session data.
     */
    public function testInFlightDecode(): void
    {
        $serialized = 'O:26:"Firehed\WebAuthn\Challenge":1:{s:3:"b64";s:44:"k' .
            'tCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=";}';
        $unserialized = unserialize($serialized);
        self::assertInstanceOf(Challenge::class, $unserialized);

        self::assertTrue(
            BinaryString::fromBase64('ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=')
                ->equals($unserialized->getBinary()),
            'Decoding resulted in inaccurate challenge',
        );
    }
}
