<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use Firehed\WebAuthn\BinaryString;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Firehed\WebAuthn\PublicKey\RSA
 */
class RSATest extends TestCase
{
    public function testPemEncodingOfKnownKey(): void
    {
        // This came from ...
        // $ openssl genpkey -algorithm RSA -out private_key.pem
        // $ openssl rsa -pubout -in private_key.pem -outform PEM -out public_key.pem
        // $ openssl rsa -pubin -in public_key.pem -text
        //
        // Public-Key: (2048 bit)
        // Modulus:
        $openSslOut = <<<'HEX'
        00:c3:04:9f:30:7d:05:90:3c:d6:52:27:3f:d2:4f:
        f4:c7:27:66:9b:71:52:2e:a9:3f:1d:81:9e:ca:5f:
        b2:36:56:2e:62:6f:76:18:70:5d:fe:59:c2:cc:5c:
        d7:7e:95:99:89:d0:10:30:1e:1e:c2:26:36:6e:df:
        b2:06:0a:32:db:fb:42:8e:6d:59:80:dd:98:33:3f:
        62:58:5c:12:02:37:08:9f:23:67:60:e2:b2:4b:7b:
        cd:18:78:0a:51:0c:83:3a:6e:8b:bb:5c:62:20:74:
        aa:a7:a8:e3:4a:c7:20:b5:0d:f6:97:d1:3e:70:9e:
        c7:7e:fa:60:49:7f:09:73:a1:ea:c6:0c:90:95:0d:
        ee:c9:5b:18:0c:f5:15:00:14:4d:46:8d:7b:95:35:
        34:92:09:4d:a3:28:b2:9e:b5:6b:46:d4:f7:77:a9:
        a4:9e:3b:c5:a9:9f:d1:01:67:03:ba:ac:e9:bb:03:
        2b:66:08:3a:63:74:2b:29:92:62:3c:b9:85:3e:94:
        77:f3:a4:1e:88:78:4f:cf:e4:9f:de:51:98:8a:d2:
        9d:5c:14:81:f3:30:3f:a2:e6:ab:60:b1:fc:d5:b8:
        80:50:1f:83:e5:59:3c:f8:60:9a:9b:ba:72:93:75:
        db:f8:63:1d:c9:ec:8b:a2:9d:f1:b7:5e:57:89:37:
        4a:d7
        HEX;
        // Strip formatting
        $hex = strtr($openSslOut, ["\n" => '', ':' => '']);
        $modulus = BinaryString::fromHex($hex);

        // Exponent: 65537 (0x10001)
        $exponent = new BinaryString("\x01\x00\x01");

        $rsa = new RSA($modulus, $exponent);
        $pemOut = $rsa->getPemFormatted();

        // (OpenSSL output)
        $expected = <<<'PEM'
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwwSfMH0FkDzWUic/0k/0
        xydmm3FSLqk/HYGeyl+yNlYuYm92GHBd/lnCzFzXfpWZidAQMB4ewiY2bt+yBgoy
        2/tCjm1ZgN2YMz9iWFwSAjcInyNnYOKyS3vNGHgKUQyDOm6Lu1xiIHSqp6jjSscg
        tQ32l9E+cJ7HfvpgSX8Jc6HqxgyQlQ3uyVsYDPUVABRNRo17lTU0kglNoyiynrVr
        RtT3d6mknjvFqZ/RAWcDuqzpuwMrZgg6Y3QrKZJiPLmFPpR386QeiHhPz+Sf3lGY
        itKdXBSB8zA/ouarYLH81biAUB+D5Vk8+GCam7pyk3Xb+GMdyeyLop3xt15XiTdK
        1wIDAQAB
        -----END PUBLIC KEY-----
        PEM;

        self::assertSame($expected, $pemOut);
    }
}
