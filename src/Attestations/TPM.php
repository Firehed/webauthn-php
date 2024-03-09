<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

class TPM implements AttestationStatementInterface
{
    private string $ver;
    private BinaryString $sig;
    private BinaryString $certInfo;
    private BinaryString $pubArea;
    // index 0: aikCert
    // index 1+ cert chain
    private array $x5c;

    public function __construct(
        array $data,
    ) {
            // [0] => alg
    // [1] => sig
    // [2] => ver
    // [3] => x5c
    // [4] => pubArea
    // [5] => certInfo
        // print_r(array_keys($data));
        $this->ver = $data['ver'];
        // $this->alg = $data['alg'];
        $this->sig = new BinaryString($data['sig']);
        $this->certInfo = new BinaryString($data['certInfo']);
        $this->pubArea = new BinaryString($data['pubArea']);
        $this->x5c = array_map(fn ($c) => new BinaryString($c), $data['x5c']);
        unset($data['sig']);
        unset($data['certInfo']);
        unset($data['pubArea']);
        unset($data['ver']);
        unset($data['x5c']);
        // alg is arrving at deprecated RS1 value
        // print_r($data);
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {

        $d = new \Firehed\CBOR\Decoder();
        var_dump($d->decode($this->pubArea->unwrap()));
        print_r($this);
        print_r($data);
        print_r($clientDataHash);
    }
}
