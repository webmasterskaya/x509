<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA1WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKey;
use Webmasterskaya\X501\ASN1\Name;
use Webmasterskaya\X509\Certificate\Extension\BasicConstraintsExtension;
use Webmasterskaya\X509\Certificate\Extension\CertificatePoliciesExtension;
use Webmasterskaya\X509\Certificate\Extension\CertificatePolicy\PolicyInformation;
use Webmasterskaya\X509\Certificate\TBSCertificate;
use Webmasterskaya\X509\Certificate\Validity;
use Webmasterskaya\X509\CertificationPath\CertificationPath;
use Webmasterskaya\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * Covers case where node is removed from valid_policy_node_set.
 *
 * @group certification-path
 *
 * @internal
 */
class CertificatePolicyIntersectionRemoveValidationIntegrationTest extends TestCase
{
    const CA_NAME = 'cn=CA';

    const INTERM_NAME = 'cn=Interm';

    const CERT_NAME = 'cn=EE';

    private static $_caKey;

    private static $_ca;

    private static $_intermKey;

    private static $_interm;

    private static $_certKey;

    private static $_cert;

    public static function setUpBeforeClass(): void
    {
        self::$_caKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-ca-rsa.pem'))->privateKeyInfo();
        self::$_intermKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-interm-rsa.pem'))->privateKeyInfo();
        self::$_certKey = PrivateKey::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem'))->privateKeyInfo();
        // create CA certificate
        $tbs = new TBSCertificate(Name::fromString(self::CA_NAME),
            self::$_caKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true),
            new CertificatePoliciesExtension(true,
                new PolicyInformation(PolicyInformation::OID_ANY_POLICY)));
        self::$_ca = $tbs->sign(new SHA1WithRSAEncryptionAlgorithmIdentifier(),
            self::$_caKey);
        // create intermediate certificate
        $tbs = new TBSCertificate(Name::fromString(self::INTERM_NAME),
            self::$_intermKey->publicKeyInfo(), Name::fromString(self::CA_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_ca);
        $tbs = $tbs->withAdditionalExtensions(
            new BasicConstraintsExtension(true, true),
            new CertificatePoliciesExtension(true,
                new PolicyInformation(PolicyInformation::OID_ANY_POLICY)));
        self::$_interm = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_caKey);
        // create end-entity certificate
        $tbs = new TBSCertificate(Name::fromString(self::CERT_NAME),
            self::$_certKey->publicKeyInfo(),
            Name::fromString(self::INTERM_NAME),
            Validity::fromStrings(null, 'now + 1 hour'));
        $tbs = $tbs->withIssuerCertificate(self::$_interm);
        $tbs = $tbs->withAdditionalExtensions(
            new CertificatePoliciesExtension(true,
                new PolicyInformation('1.3.6.1.3.1'),
                new PolicyInformation('1.3.6.1.3.2')));
        self::$_cert = $tbs->sign(
            new SHA1WithRSAEncryptionAlgorithmIdentifier(), self::$_intermKey);
    }

    public static function tearDownAfterClass(): void
    {
        self::$_caKey = null;
        self::$_ca = null;
        self::$_intermKey = null;
        self::$_interm = null;
        self::$_certKey = null;
        self::$_cert = null;
    }

    public function testValidate()
    {
        $path = new CertificationPath(self::$_ca, self::$_interm, self::$_cert);
        $config = new PathValidationConfig(new DateTimeImmutable(), 3);
        $config = $config->withPolicySet('1.3.6.1.3.2');
        $result = $path->validate($config);
        $this->assertCount(1, $result->policies());
    }
}
