<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

trait ChallengeManagerTestTrait
{
    abstract protected function getChallengeManager(): ChallengeManagerInterface;

    public function testCreateChallengeIsUnique(): void
    {
        $cm = $this->getChallengeManager();
        $c1 = $cm->createChallenge();
        $c2 = $cm->createChallenge();
        self::assertNotSame($c1, $c2);
        self::assertNotSame($c1->getBase64(), $c2->getBase64());
    }

    public function testMostRecentChallengeCanBeRetrieved(): void
    {
        $cm = $this->getChallengeManager();
        $c = $cm->createChallenge();
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);
        self::assertInstanceOf(ChallengeInterface::class, $found);
        self::assertSame($c->getBase64(), $found->getBase64());
    }

    public function testMostRecentChallengeCanBeRetrievedOnlyOnce(): void
    {
        $cm = $this->getChallengeManager();
        $c = $cm->createChallenge();
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);
        $again = $cm->useFromClientDataJSON($cdjValue);

        self::assertInstanceOf(ChallengeInterface::class, $found);
        self::assertNull($again);
    }

    public function testNoChallengeIsReturnedIfManagerIsEmpty(): void
    {
        $cm = $this->getChallengeManager();

        $c = Challenge::random();
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);

        self::assertNull($found);
    }

    public function testRetrievalDoesNotCreateChallengeFromUserData(): void
    {
        $cm = $this->getChallengeManager();
        $c = $cm->createChallenge();

        $userChallenge = Challenge::random();
        $cdjValue = $userChallenge->getBinary()->toBase64Url();

        $retrieved = $cm->useFromClientDataJSON($cdjValue);
        // The implmentation may return the previously-stored value or null,
        // but MUST NOT attempt to reconstruct the challenge from the user-
        // provided value.
        self::assertNotSame($userChallenge->getBase64(), $retrieved?->getBase64());
    }
}
