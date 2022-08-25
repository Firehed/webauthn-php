<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use BadMethodCallException;
use OutOfRangeException;

/**
 * @internal
 *
 * @link https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
 *
 * @phpstan-type AttestedCredentialData array{
 *   aaguid: BinaryString,
 *   credentialId: BinaryString,
 *   credentialPublicKey: BinaryString,
 * }
 */
class AuthenticatorData
{
    private bool $isUserPresent;

    private bool $isUserVerified;

    private BinaryString $rpIdHash;

    private int $signCount;

    /**
     * @var ?AttestedCredentialData Attested Credential Data
     */
    private $ACD;

    /** @var null RESERVED: WebAuthn Extensions */
    private $extensions;

    /**
     * @see https://w3c.github.io/webauthn/#sec-authenticator-data
     * WebAuthn 6.1
     */
    public static function parse(BinaryString $raw): AuthenticatorData
    {
        $bytes = $raw->unwrap();
        assert(strlen($bytes) >= 37);

        $offset = 0;

        $rpIdHash = substr($bytes, 0, 32);
        $offset += 32;

        $flags = unpack('c', $bytes, $offset)[1];
        $offset += 1; // c = 1 byte

        $UP = ($flags & 0x01) === 0x01; // bit 0: User Present
        $UV = ($flags & 0x04) === 0x04; // bit 2: User Verified
        $AT = ($flags & 0x40) === 0x40; // bit 6: Attested credential data incl.
        $ED = ($flags & 0x80) === 0x80; // bit 7: Extension data incl.

        $signCount = unpack('N', $bytes, $offset)[1];
        $offset += 4; // N = 4 byyes

        $authData = new AuthenticatorData();
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->rpIdHash = new BinaryString($rpIdHash);
        $authData->signCount = $signCount;

        // $restOfBytes = substr($bytes, $offset);
        // $restOfBytesLength = strlen($restOfBytes);
        if ($AT) {
            // https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sec-attested-credential-data
            // assert($restOfBytesLength >= 18);
            // $aaguid = substr($restOfBytes, 0, 16);
            // $credentialIdLength = unpack('n', $restOfBytes, 16)[1];
            // assert($restOfBytesLength >= (18 + $credentialIdLength));

            $aaguid = substr($bytes, $offset, 16);
            $offset += 16;

            $credentialIdLength = unpack('n', $bytes, $offset)[1];
            $offset += 2; // n = 2 bytes

            $credentialId = substr($bytes, $offset, $credentialIdLength);
            $offset += $credentialIdLength;

            // This needs to peek into the remaining data to parse the start of
            // the COSE format to know the legnth of the public key. Where ED=0
            // this should go to the end of the string, but if that's set this
            // will read too far.
            // $rawCredentialPublicKey = substr($restOfBytes, 18 + $credentialIdLength);
            $rawCredentialPublicKey = substr($bytes, $offset);

            $authData->ACD = [
                'aaguid' => new BinaryString($aaguid),
                'credentialId' => new BinaryString($credentialId),
                'credentialPublicKey' => new BinaryString($rawCredentialPublicKey),
            ];
        }
        if ($ED) {
            // @codeCoverageIgnoreStart
            throw new BadMethodCallException('Not implemented yet');
            // @codeCoverageIgnoreEnd
        }

        return $authData;
    }

    public function getAttestedCredential(): CredentialInterface
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

        return new Credential(
            $this->ACD['credentialId'],
            new COSEKey($this->ACD['credentialPublicKey']),
            $this->signCount,
        );
    }

    public function getRpIdHash(): BinaryString
    {
        return $this->rpIdHash;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function isUserPresent(): bool
    {
        return $this->isUserPresent;
    }

    public function isUserVerified(): bool
    {
        return $this->isUserVerified;
    }
}
