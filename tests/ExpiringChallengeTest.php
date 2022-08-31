<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DateInterval;

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

    public function testPastExpirationThrowsWhenGettingBinary(): void
    {
        $interval = new DateInterval('PT2S');
        $interval->invert = 1; // Negative
        $ec = new ExpiringChallenge($interval);

        self::expectException(Errors\ExpiredChallengeError::class);
        $ec->getBinary();
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
}
