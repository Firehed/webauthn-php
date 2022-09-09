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

    protected function getInFlightSerialized(): string
    {
        return 'O:26:"Firehed\WebAuthn\Challenge":1:{s:3:"b64";s:44:"ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=";}';
    }

    protected function getInFlightChallenge(): BinaryString
    {
        return BinaryString::fromBase64('ktCbjFzaUuHixxmUFk9G35Yd0EZdWp5+RcHlKdsIK58=');
    }
}
