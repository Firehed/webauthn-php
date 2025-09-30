<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Challenge::class)]
class ChallengeTest extends TestCase
{
    use ChallengeInterfaceTestTrait;

    protected function getChallenge(): ChallengeInterface
    {
        return Challenge::random();
    }

    protected function getInFlightSerialized(): string
    {
        return 'O:26:"Firehed\WebAuthn\Challenge":1:{s:3:"b64";s:44:"ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=";}';
    }

    protected function getInFlightChallenge(): BinaryString
    {
        return BinaryString::fromBase64('ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=');
    }
}
