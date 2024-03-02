<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Trait for adding PHPUnit test cases to both packaged and custom
 * ChallengeManagerInterface implementations.
 *
 * @api
 */
trait ChallengeManagerTestTrait
{
    use ChallengeLoaderTestTrait;

    protected function getChallengeLoaderManagingChallenge(ChallengeInterface $challenge): ChallengeLoaderInterface
    {
        $cm = $this->getChallengeManager();
        $cm->manageChallenge($challenge);
        return $cm;
    }

    abstract protected function getChallengeManager(): ChallengeManagerInterface;

    public function testMostRecentChallengeCanBeRetrieved(): void
    {
        $cm = $this->getChallengeManager();
        $c = $this->createChallenge();
        $cm->manageChallenge($c);
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);
        self::assertInstanceOf(ChallengeInterface::class, $found);
        self::assertSame($c->getBase64(), $found->getBase64());
    }

    public function testMostRecentChallengeCanBeRetrievedOnlyOnce(): void
    {
        $cm = $this->getChallengeManager();
        $c = $this->createChallenge();
        $cm->manageChallenge($c);
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);
        $again = $cm->useFromClientDataJSON($cdjValue);

        self::assertInstanceOf(ChallengeInterface::class, $found);
        self::assertNull($again);
    }

    public function testNoChallengeIsReturnedIfManagerIsEmpty(): void
    {
        $cm = $this->getChallengeManager();

        $c = $this->createChallenge();
        // Do NOT manage it
        $cdjValue = $c->getBinary()->toBase64Url();

        $found = $cm->useFromClientDataJSON($cdjValue);

        self::assertNull($found);
    }

    public function testRetrievalDoesNotCreateChallengeFromUserData(): void
    {
        $cm = $this->getChallengeManager();
        $c = $this->createChallenge();
        $cm->manageChallenge($c);

        $userChallenge = $this->createChallenge();
        $cdjValue = $userChallenge->getBinary()->toBase64Url();

        $retrieved = $cm->useFromClientDataJSON($cdjValue);
        // The implmentation may return the previously-stored value or null,
        // but MUST NOT attempt to reconstruct the challenge from the user-
        // provided value.
        self::assertNotSame($userChallenge->getBase64(), $retrieved?->getBase64());
    }

    private function createChallenge(): ChallengeInterface
    {
        return Challenge::random();
    }
}
