<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Trait for adding PHPUnit test cases to both packaged and custom
 * ChallengeLoaderInterface implementations.
 *
 * @api
 */
trait ChallengeLoaderTestTrait
{
    public function testChallengeCannotBeRetrievedTwice(): void
    {
        $c = Challenge::random();
        $cl = $this->getChallengeLoaderManagingChallenge($c);

        $result = $cl->useFromClientDataJSON($c->getBase64Url());
        $result2 = $cl->useFromClientDataJSON($c->getBase64Url());

        self::assertNotNull($result);
        self::assertSame($c->getBase64Url(), $result->getBase64Url());
        self::assertNull($result2);
    }

    public function testManagerDoesNotReturnUnmanagedChallenge(): void
    {
        $c = Challenge::random();
        $cl = $this->getChallengeLoaderManagingChallenge($c);

        $c2 = Challenge::random();
        assert($c->getBase64Url() !== $c2->getBase64Url());
        self::assertNull($cl->useFromClientDataJSON($c2->getBase64Url()));
    }

    abstract protected function getChallengeLoaderManagingChallenge(
        ChallengeInterface $challenge,
    ): ChallengeLoaderInterface;
}
