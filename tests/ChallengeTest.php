<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversDefaultClass Firehed\WebAuthn\Challenge
 * @covers ::<protected>
 * @covers ::<private>
 */
class ChallengeTest extends \PHPUnit\Framework\TestCase
{
    public function testSerializationRoundTrip(): void
    {
        $challenge = Challenge::random();

        $serialized = serialize($challenge);
        $unserialized = unserialize($serialized);

        self::assertInstanceOf(Challenge::class, $unserialized);
        self::assertTrue(
            hash_equals($challenge->getChallenge(), $unserialized->getChallenge()),
            'Wrapped challenge changed',
        );
    }

    /**
     * This covers the specific scenario of a challenge being unserialized
     * (e.g. from a Session) that was generated from an older version of this
     * library. This helps ensure compatibility across versions and reduces the
     * risk of a point release breaking any active session data.
     */
    public function testInflightDecode(): void
    {
        $serialized = 'O:26:"Firehed\WebAuthn\Challenge":1:{s:3:"b64";s:44:"ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=";}';
        $unserialized = unserialize($serialized);
        self::assertInstanceOf(Challenge::class, $unserialized);

        self::assertTrue(
            hash_equals(
                base64_decode('ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=', true),
                $unserialized->getChallenge(),
            ),
            'Decoding resulted in inaccurate challenge',
        );
    }
}
