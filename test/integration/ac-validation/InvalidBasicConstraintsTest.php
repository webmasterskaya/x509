<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoEncoding\PEMBundle;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA512AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Webmasterskaya\X501\ASN1\Name;
use Webmasterskaya\X509\AttributeCertificate\AttCertIssuer;
use Webmasterskaya\X509\AttributeCertificate\AttCertValidityPeriod;
use Webmasterskaya\X509\AttributeCertificate\AttributeCertificateInfo;
use Webmasterskaya\X509\AttributeCertificate\Attributes;
use Webmasterskaya\X509\AttributeCertificate\Holder;
use Webmasterskaya\X509\AttributeCertificate\Validation\ACValidationConfig;
use Webmasterskaya\X509\AttributeCertificate\Validation\ACValidator;
use Webmasterskaya\X509\Certificate\Certificate;
use Webmasterskaya\X509\Certificate\CertificateBundle;
use Webmasterskaya\X509\Certificate\Extension\BasicConstraintsExtension;
use Webmasterskaya\X509\Certificate\Extension\KeyUsageExtension;
use Webmasterskaya\X509\Certificate\TBSCertificate;
use Webmasterskaya\X509\Certificate\Validity;
use Webmasterskaya\X509\CertificationPath\CertificationPath;
use Webmasterskaya\X509\Exception\X509ValidationException;

/**
 * @group ac-validation
 *
 * @internal
 */
class InvalidBasicConstraintsACValidationIntegrationTest extends TestCase
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
        $issuer_ca = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-interm-ecdsa.pem'));
        $issuer_ca_pk = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-ec.pem'));
        $issuer_pk = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ec.pem'));
        // create issuer certificate
        $tbs = new TBSCertificate(Name::fromString('cn=AC CA'),
            $issuer_pk->publicKeyInfo(), new Name(),
            Validity::fromStrings('now', 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate($issuer_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new KeyUsageExtension(true, KeyUsageExtension::DIGITAL_SIGNATURE),
            new BasicConstraintsExtension(true, true));
        $issuer = $tbs->sign(new ECDSAWithSHA512AlgorithmIdentifier(),
            $issuer_ca_pk);
        self::$_holderPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $holder, $interms);
        self::$_issuerPath = CertificationPath::fromTrustAnchorToTarget(
            $root_ca, $issuer, $interms);
        $aci = new AttributeCertificateInfo(Holder::fromPKC($holder),
            AttCertIssuer::fromPKC($issuer),
            AttCertValidityPeriod::fromStrings('now', 'now + 1 hour'),
            new Attributes());
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
        $validator = new ACValidator(self::$_ac, $config);
        $this->expectException(X509ValidationException::class);
        $validator->validate();
    }
}
