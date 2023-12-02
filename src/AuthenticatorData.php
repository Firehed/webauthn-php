<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use BadMethodCallException;
use OutOfRangeException;

/**
 * @internal
 *
 * @link https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
 */
class AuthenticatorData
{
    private bool $isBackupEligible;
    private bool $isBackedUp;
    private bool $isUserPresent;

    private bool $isUserVerified;

    private BinaryString $rpIdHash;

    private int $signCount;

    private ?AttestedCredentialData $ACD = null;

    private BinaryString $original;
    /**
     * @see https://w3c.github.io/webauthn/#sec-authenticator-data
     * WebAuthn 6.1
     */
    public static function parse(BinaryString $bytes): AuthenticatorData
    {
        $rpIdHash = $bytes->read(32);

        $flags = $bytes->readUint8();
        $UP = ($flags & 0x01) === 0x01; // bit 0: User Present
        // 0x02: RFU1
        $UV = ($flags & 0x04) === 0x04; // bit 2: User Verified
        $BE = ($flags & 0x08) === 0x08; // bit 3: Backup Eligibility
        $BS = ($flags & 0x10) === 0x10; // bit 4: Backup State
        // 0x20: RFU2
        $AT = ($flags & 0x40) === 0x40; // bit 6: Attested credential data incl.
        $ED = ($flags & 0x80) === 0x80; // bit 7: Extension data incl.

        if ($BS) {
            assert($BE === true, 'Backup state is true when not eligible');
        }

        $signCount = $bytes->readUint32();

        $authData = new AuthenticatorData();
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->isBackupEligible = $BE;
        $authData->isBackedUp = $BS;
        $authData->rpIdHash = new BinaryString($rpIdHash);
        $authData->signCount = $signCount;
        $authData->original = $bytes;

        if ($AT) {
            // https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sec-attested-credential-data
            $aaguid = $bytes->read(16);
            $credentialIdLength = $bytes->readUint16();
            $credentialId = $bytes->read($credentialIdLength);

            // This needs to peek into the remaining data to parse the start of
            // the COSE format to know the legnth of the public key. Where ED=0
            // this should go to the end of the string, but if that's set this
            // will read too far.
            // FIXME: support extension data & offset handling
            $rawCredentialPublicKey = $bytes->getRemaining();

            $authData->ACD = new AttestedCredentialData(
                aaguid: new BinaryString($aaguid),
                credentialId: new BinaryString($credentialId),
                coseKey: new COSEKey(new BinaryString($rawCredentialPublicKey)),
            );
        }
        if ($ED) {
            // @codeCoverageIgnoreStart
            throw new BadMethodCallException('Not implemented yet');
            // @codeCoverageIgnoreEnd
        }

        return $authData;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        if ($this->ACD === null) {
            throw new OutOfRangeException(
                'The authenticator data does not contain an attested ' .
                'credential. This is expected behavior for verify ' .
                '(credentials.get()) results, and registration ' .
                '(credentials.create()) results where publicKey.attestation ' .
                '!= "direct". If you encountered this error on a ' .
                'registration where attestation is direct, please file a bug ' .
                'including the JSON request, the Javascript publicKey ' .
                'creation object, and the type of authentictor that was used.'
            );
        }

        return $this->ACD;
    }

    public function getRpIdHash(): BinaryString
    {
        return $this->rpIdHash;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function isBackupEligible(): bool
    {
        return $this->isBackupEligible;
    }

    public function isBackedUp(): bool
    {
        return $this->isBackedUp;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function isUserVerified(): bool
    {
        return $this->isUserVerified;
    }
    public function getRaw(): BinaryString
    {
        return $this->original;
    }
}
