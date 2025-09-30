<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(SessionChallengeManager::class)]
class SessionChallengeManagerTest extends TestCase
{
    use ChallengeManagerTestTrait;

    protected function setUp(): void
    {
        session_reset();
    }

    protected function getChallengeManager(): ChallengeManagerInterface
    {
        return new SessionChallengeManager();
    }
}
