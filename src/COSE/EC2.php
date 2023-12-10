<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\PublicKey;

class EC2 implements KeyInterface
{
    // 13.1.1-13.2
    private const INDEX_CURVE = -1;
    private const INDEX_X_COORDINATE = -2;
    private const INDEX_Y_COORDINATE = -3;
    private const INDEX_PRIVATE_KEY = -4;

    private Algorithm $algorithm;
    private Curve $curve;

    private BinaryString $x;
    private BinaryString $y;

    public function __construct(array $params)
    {
        assert($params[KeyType::COSE_INDEX] === KeyType::EllipticCurve->value);

        $this->algorithm = Algorithm::from($params[Algorithm::COSE_INDEX]);
        $this->curve = Curve::from($params[self::INDEX_CURVE]);

        $this->x = new BinaryString($params[self::INDEX_X_COORDINATE]);
        $this->y = new BinaryString($params[self::INDEX_Y_COORDINATE]);
    }

    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return new PublicKey\EllipticCurve($this->x, $this->y);
    }

    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }
}
