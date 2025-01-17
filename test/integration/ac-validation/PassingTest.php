<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Webmasterskaya\X509\AttributeCertificate\AttCertIssuer;
use Webmasterskaya\X509\AttributeCertificate\AttCertValidityPeriod;
use Webmasterskaya\X509\AttributeCertificate\AttributeCertificate;
use Webmasterskaya\X509\AttributeCertificate\AttributeCertificateInfo;
use Webmasterskaya\X509\AttributeCertificate\Attributes;
use Webmasterskaya\X509\AttributeCertificate\Holder;
use Webmasterskaya\X509\AttributeCertificate\Validation\ACValidationConfig;
use Webmasterskaya\X509\AttributeCertificate\Validation\ACValidator;
use Webmasterskaya\X509\Certificate\Certificate;
use Webmasterskaya\X509\Certificate\CertificateBundle;
use Webmasterskaya\X509\Certificate\Extension\Target\TargetName;
use Webmasterskaya\X509\Certificate\Extension\TargetInformationExtension;
use Webmasterskaya\X509\CertificationPath\CertificationPath;
use Webmasterskaya\X509\GeneralName\DNSName;

/**
 * @group ac-validation
 *
 * @internal
 */
class PassingACValidationIntegrationTest extends TestCase
{
    private static $_holderPath;

    private static $_issuerPath;

    private static $_ac;

    public static function setUpBeforeClass(): void
    {
        $root_ca = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $interms = CertificateBundle::fromPEMBundle(
            PEMBundle::fromFile(
                TEST_ASSETS_DIR . '/certs/intermediate-bundle.pem'));
        $holder = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $issuer = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $issuer_pk = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $holder, $interms);
        self::$_issuerPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $issuer, $interms);
        $aci = new AttributeCertificateInfo(Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings('now', 'now + 1 hour'),
            new Attributes());
        $aci = $aci->withAdditionalExtensions(
            TargetInformationExtension::fromTargets(
                new TargetName(new DNSName('test'))));
        self::$_ac = $aci->sign(new ECDSAWithSHA256AlgorithmIdentifier(),
            $issuer_pk);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_holderPath = null;
        self::$_issuerPath = null;
        self::$_ac = null;
    }

    public function testValidate()
    {
        $config = new ACValidationConfig(self::$_holderPath, self::$_issuerPath);
        $config = $config->withTargets(new TargetName(new DNSName('test')));
        $validator = new ACValidator(self::$_ac, $config);
        $this->assertInstanceOf(AttributeCertificate::class,
            $validator->validate());
    }
}
