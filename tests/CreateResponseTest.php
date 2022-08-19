<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversDefaultClass Firehed\WebAuthn\CreateResponse
 * @covers ::<protected>
 * @covers ::<private>
 */
class CreateResponseTest extends \PHPUnit\Framework\TestCase
{
    // 7.1.7
    public function testCDJTypeMismatchIsError(): void
    {
        // override CDJ
    }

    // 7.1.8
    public function testCDJChallengeMismatchIsError(): void
    {
        // override CDJ
    }

    // 7.1.9
    public function testCDJOriginMismatchIsError(): void
    {
        // override CDJ
    }

    // 7.1.13
    public function testRelyingPartyIdMismatchIsError(): void
    {
        // override authData
    }

    // 7.1.14
    public function testUserNotPresentIsError(): void
    {
        // override authData
    }

    // 7.1.15
    public function testUserVerifiedNotPresentWhenRequiredIsError(): void
    {
        // (default data ok)
        // call verify with UVR::Required
    }

    // 7.1.16
    public function testPubKeyAlgorithmNotMatchingOptionsIsError(): void
    {
        self::markTestSkipped('Only EC2/ED256 supported at this time');
    }

    // 7.1.19
    public function testFormatSpecificVerificationOccurs(): void
    {
        // CreateResponse.ao.stmt
        // = createMock(AttestationStatementInterface::class)
        // ->expects(self::once())
        // ->method('verify')
        // ->with(...)
        // ->willReturn(...)
        //
        // or AO itself gets interfaced and mocked diectly?
    }
    // format-specific tests of verification? these should get tested
        //
    // separately. Need to create an AttestationObject with a mocked
}
