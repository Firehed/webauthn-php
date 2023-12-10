<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Any class implementing ChallengeInterface can use this trait and get some
 * automatic unit test coverage
 */
trait ChallengeInterfaceTestTrait
{
    abstract protected function getChallenge(): ChallengeInterface;

    public function testSerializationRoundTrip(): void
    {
        $challenge = $this->getChallenge();

        $serialized = serialize($challenge);
        $unserialized = unserialize($serialized);

        self::assertInstanceOf(ChallengeInterface::class, $unserialized);
        self::assertTrue(
            $challenge->getBinary()->equals($unserialized->getBinary()),
            'Wrapped challenge changed',
        );

        self::assertSame(
            $challenge->getBase64(),
            $unserialized->getBase64(),
            'Base64 changed',
        );
    }

    public function testBinaryMatchesBase64(): void
    {
        $challenge = $this->getChallenge();

        $binary = $challenge->getBinary();
        $base64 = $challenge->getBase64();
        $base64Url = $challenge->getBase64Url();

        self::assertSame(
            $base64,
            base64_encode($binary->unwrap()),
            'Base64 encoding the unwrapped binary did not match getBase64 result',
        );

        self::assertSame(
            $base64Url,
            $binary->toBase64Url(),
            'Base64URL encoding was incorrect',
        );
    }

    /**
     * This covers the specific scenario of a challenge being unserialized
     * (e.g. from a Session) that was generated from an older version of this
     * library. This helps ensure compatibility across versions and reduces the
     * risk of a point release breaking any active session data.
     */
    public function testInFlightDecode(): void
    {
        $serialized = $this->getInFlightSerialized();
        $unserialized = unserialize($serialized);
        self::assertInstanceOf(ChallengeInterface::class, $unserialized);

        self::assertTrue(
            $this->getInFlightChallenge()->equals($unserialized->getBinary()),
            'Decoding resulted in inaccurate challenge',
        );
    }

    abstract protected function getInFlightSerialized(): string;
    abstract protected function getInFlightChallenge(): BinaryString;
}
