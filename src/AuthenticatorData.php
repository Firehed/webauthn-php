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
 *   aaguid: string,
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

        $rpIdHash = substr($bytes, 0, 32);
        $flags = ord(substr($bytes, 32, 1));
        $UP = ($flags & 0x01) === 0x01; // bit 0: User Present
        $UV = ($flags & 0x04) === 0x04; // bit 2: User Verified
        $AT = ($flags & 0x40) === 0x40; // bit 6: Attested credential data incl.
        $ED = ($flags & 0x80) === 0x80; // bit 7: Extension data incl.
        $signCount = unpack('N', substr($bytes, 33, 4))[1];

        $authData = new AuthenticatorData();
        $authData->isUserPresent = $UP;
        $authData->isUserVerified = $UV;
        $authData->rpIdHash = new BinaryString($rpIdHash);
        $authData->signCount = $signCount;

        $restOfBytes = substr($bytes, 37);
        $restOfBytesLength = strlen($restOfBytes);
        if ($AT) {
            // https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sec-attested-credential-data
            assert($restOfBytesLength >= 18);

            $aaguid = substr($restOfBytes, 0, 16);
            $credentialIdLength = unpack('n', substr($restOfBytes, 16, 2))[1];
            assert($restOfBytesLength >= (18 + $credentialIdLength));
            $credentialId = substr($restOfBytes, 18, $credentialIdLength);

            // This needs to peek into the remaining data to parse the start of
            // the COSE format to know the legnth of the public key. Where ED=0
            // this should go to the end of the string, but if that's set this
            // will read too far.
            $rawCredentialPublicKey = substr($restOfBytes, 18 + $credentialIdLength);

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

    /**
     * @return array{
     *   isUserPresent: bool,
     *   isUserVerified: bool,
     *   rpIdHash: string,
     *   signCount: int,
     *   ACD?: array{
     *     aaguid: string,
     *     credentialId: string,
     *     credentialPublicKey: array{
     *       kty: int,
     *       alg: ?int,
     *       crv: int,
     *       x: string,
     *       y: string,
     *       d: string,
     *     },
     *   },
     * }
     * FIXME: move key compoenents to COSEKey?
     */
    public function __debugInfo(): array
    {
        $hex = function ($str) {
            return '0x' . bin2hex($str);
        };
        $data = [
            'isUserPresent' => $this->isUserPresent,
            'isUserVerified' => $this->isUserVerified,
            'rpIdHash' => $hex($this->rpIdHash),
            'signCount' => $this->signCount,
        ];

        if ($this->ACD !== null) {
            // See RFC8152 section 7 (COSE key parameters)
            $pk = [
                'kty' => $this->ACD['credentialPublicKey'][1], // MUST be 'EC2' (sec 13 tbl 21)
                // kid = 2
                'alg' => $this->ACD['credentialPublicKey'][3] ?? null,
                // key_ops = 4 // must include sign (1)/verify(2) if present, depending on usage
                // Base IV = 5

                // this would be 'k' if 'kty'===4(Symmetric)
                'crv' => $this->ACD['credentialPublicKey'][-1], // (13.1 tbl 22)
                'x' => $hex($this->ACD['credentialPublicKey'][-2] ?? ''), // (13.1.1 tbl 23/13.2 tbl 24)
                'y' => $hex($this->ACD['credentialPublicKey'][-3] ?? ''), // (13.1.1 tbl 23)
                'd' => $hex($this->ACD['credentialPublicKey'][-4] ?? ''), // (13.2 tbl 24)

            ];
            $acd = [
                'aaguid' => $hex($this->ACD['aaguid']),
                'credentialId' => $hex($this->ACD['credentialId']),
                'credentialPublicKey' => $pk,
            ];
            $data['ACD'] = $acd;
        }
        return $data;
    }
}
