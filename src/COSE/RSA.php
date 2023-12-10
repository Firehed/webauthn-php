<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\PublicKey;

class RSA implements KeyInterface
{
    private Algorithm $algorithm;

    private BinaryString $n;
    private BinaryString $e;

    public function __construct(array $params)
    {
        assert($params[KeyType::COSE_INDEX] === KeyType::Rsa->value);

        $this->algorithm = Algorithm::from($params[Algorithm::COSE_INDEX]);

        $this->n = new BinaryString($params[-1]);
        $this->e = new BinaryString($params[-2]);

        // print_r($this);
    }

    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
    }

    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }
}
