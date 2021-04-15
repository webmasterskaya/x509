<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKey;
use Sop\X501\ASN1\Name;
use Webmasterskaya\X509\Certificate\Extension\BasicConstraintsExtension;
use Webmasterskaya\X509\Certificate\Extension\CertificatePoliciesExtension;
use Webmasterskaya\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Webmasterskaya\X509\Certificate\TBSCertificate;
use Webmasterskaya\X509\Certificate\Validity;
use Webmasterskaya\X509\CertificationPath\CertificationPath;
use Webmasterskaya\X509\CertificationPath\PathValidation\PathValidationConfig;
use Webmasterskaya\X509\CertificationPath\PathValidation\PathValidationResult;

/**
 * Cover policy information processing.
 *
 * @group certification-path
 *
 * @internal
 */
class CertificatePoliciesValidationIntegrationTest extends TestCase
{
    const CA_NAME = 'cn=CA';

    const CERT_NAME = 'cn=EE';

    private static $_caKey;

    private static $_ca;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true, 1),
            new CertificatePoliciesExtension(false,
                new PolicyInformation('1.3.6.1.3')));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new CertificatePoliciesExtension(false,
                new PolicyInformation('1.3.6.1.3')));
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_cert);
        $config = new PathValidationConfig(new DateTimeImmutable(), 3);
        $config = $config->withExplicitPolicy(true);
        $result = $path->validate($config);
        $this->assertInstanceOf(PathValidationResult::class, $result);
    }
}
