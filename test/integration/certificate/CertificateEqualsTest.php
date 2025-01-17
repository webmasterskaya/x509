<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKey;
use Webmasterskaya\CryptoTypes\Asymmetric\PublicKeyInfo;
use Webmasterskaya\X509\Certificate\Certificate;

/**
 * @group certificate
 *
 * @internal
 */
class CertificateEqualsIntegrationTest extends TestCase
{
    private static $_cert1;

    private static $_cert1DifKey;

    private static $_cert2;

    public static function setUpBeforeClass(): void
    {
        self::$_cert1 = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $pubkey = PublicKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $tbs = self::$_cert1->tbsCertificate()->withSubjectPublicKeyInfo(
            $pubkey);
        $privkey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
        self::$_cert1DifKey = $tbs->sign(self::$_cert1->signatureAlgorithm(),
            $privkey);
        self::$_cert2 = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_cert1 = null;
        self::$_cert1DifKey = null;
        self::$_cert2 = null;
    }

    public function testEquals()
    {
        $this->assertTrue(self::$_cert1->equals(self::$_cert1));
    }

    public function testNotEquals()
    {
        $this->assertFalse(self::$_cert1->equals(self::$_cert2));
    }

    public function testDifferentPubKeyNotEquals()
    {
        $this->assertFalse(self::$_cert1->equals(self::$_cert1DifKey));
    }
}
