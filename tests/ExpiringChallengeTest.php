<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DateInterval;
use LogicException;

/**
 * @covers Firehed\WebAuthn\ExpiringChallenge
 */
class ExpiringChallengeTest extends \PHPUnit\Framework\TestCase
{
    use ChallengeInterfaceTestTrait;

    protected function getChallenge(): ChallengeInterface
    {
        return new ExpiringChallenge(new DateInterval('PT2S'));
    }

    /**
     * @doesNotPerformAssertions This is checking that an exeption is NOT
     * thrown when the expiration is in the future.
     */
    public function testFutureExpirationOkWhenGettingBase64(): void
    {
        $ec = new ExpiringChallenge(new DateInterval('PT2S'));

        // This should not throw.
        $_ = $ec->getBase64();
    }

    /**
     * @doesNotPerformAssertions This is checking that an exeption is NOT
     * thrown when the expiration is in the future.
     */
    public function testFutureExpirationOkWhenGettingBinary(): void
    {
        $ec = new ExpiringChallenge(new DateInterval('PT2S'));

        // This should not throw.
        $_ = $ec->getBinary();
    }

    public function testPastExpirationThrowsWhenGettingBase64(): void
    {
        $interval = new DateInterval('PT2S');
        $interval->invert = 1; // Negative
        $ec = new ExpiringChallenge($interval);

        self::expectException(Errors\ExpiredChallengeError::class);
        $ec->getBase64();
    }

    public function testPastExpirationThrowsWhenGettingBase64Url(): void
    {
        $interval = new DateInterval('PT2S');
        $interval->invert = 1; // Negative
        $ec = new ExpiringChallenge($interval);

        self::expectException(Errors\ExpiredChallengeError::class);
        $ec->getBase64Url();
    }

    public function testPastExpirationThrowsWhenGettingBinary(): void
    {
        $interval = new DateInterval('PT2S');
        $interval->invert = 1; // Negative
        $ec = new ExpiringChallenge($interval);

        self::expectException(Errors\ExpiredChallengeError::class);
        $ec->getBinary();
    }

    /**
     * @doesNotPerformAssertions This is checking that an exeption is NOT
     * thrown when the expiration is in the future.
     */
    public function testFactoryInFuture(): void
    {
        $ec = ExpiringChallenge::withLifetime(86400);
        $_ = $ec->getBase64();
    }

    public function testFactoryRightNow(): void
    {
        self::expectException(LogicException::class);
        // @phpstan-ignore-next-line Validating runtime check
        $ec = ExpiringChallenge::withLifetime(0);
    }

    public function testFactoryInPast(): void
    {
        self::expectException(LogicException::class);
        // @phpstan-ignore-next-line Validating runtime check
        $ec = ExpiringChallenge::withLifetime(-1);
    }

    /**
     * @doesNotPerformAssertions This indirectly asserts that exceptions are
     * thrown
     *
     * @medium
     */
    public function testExpirationByWaiting(): void
    {
        $ec = new ExpiringChallenge(new DateInterval('PT1S'));
        $_ = $ec->getBase64();
        $_ = $ec->getBinary();

        sleep(1);
        try {
            $_ = $ec->getBase64();
            self::fail('getBase64 did not throw');
        } catch (Errors\ExpiredChallengeError) {
        }

        try {
            $_ = $ec->getBinary();
            self::fail('getBinary did not throw');
        } catch (Errors\ExpiredChallengeError) {
        }
    }

    protected function getInFlightSerialized(): string
    {
        $nearFuture = time() + 10;
        // This is ABSOLUTELY RIDICULOUS, but to bypass the expiration time so
        // the wrapped challenge can be read out, this needs to dynamiaclly
        // override the expiration in the serialized format. There's no good
        // alternative I can think of that doesn't involve a) allowing the
        // expiration to change or b) providing some sort of test-only hack
        // method to accomplish the same.
        return 'O:34:"Firehed\WebAuthn\ExpiringChallenge":2:{s:1:"c";s:44:"Vi' .
            'FgIH5w+B1BzVRWatX+Zjvt2D9JxQCAH6PnJwW+QdQ=";s:1:"e";i:' .
            $nearFuture . ';}';
    }

    protected function getInFlightChallenge(): BinaryString
    {
        return BinaryString::fromBase64('ViFgIH5w+B1BzVRWatX+Zjvt2D9JxQCAH6PnJwW+QdQ=');
    }
}
