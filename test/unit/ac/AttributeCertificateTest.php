<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Webmasterskaya\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Webmasterskaya\CryptoTypes\Signature\Signature;
use Webmasterskaya\X501\ASN1\Name;
use Webmasterskaya\X509\AttributeCertificate\AttCertIssuer;
use Webmasterskaya\X509\AttributeCertificate\AttCertValidityPeriod;
use Webmasterskaya\X509\AttributeCertificate\Attribute\RoleAttributeValue;
use Webmasterskaya\X509\AttributeCertificate\AttributeCertificate;
use Webmasterskaya\X509\AttributeCertificate\AttributeCertificateInfo;
use Webmasterskaya\X509\AttributeCertificate\Attributes;
use Webmasterskaya\X509\AttributeCertificate\Holder;
use Webmasterskaya\X509\AttributeCertificate\IssuerSerial;
use Webmasterskaya\X509\Certificate\Certificate;
use Webmasterskaya\X509\GeneralName\DirectoryName;
use Webmasterskaya\X509\GeneralName\GeneralNames;
use Webmasterskaya\X509\GeneralName\UniformResourceIdentifier;

/**
 * @group ac
 *
 * @internal
 */
class AttributeCertificateTest extends TestCase
{
    private static $_acPem;

    private static $_privateKeyInfo;

    public static function setUpBeforeClass(): void
    {
        self::$_acPem = PEM::fromFile(TEST_ASSETS_DIR . '/ac/acme-ac.pem');
        self::$_privateKeyInfo = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/private_key.pem'));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_acPem = null;
        self::$_privateKeyInfo = null;
    }

    public function testCreate()
    {
        $holder = new Holder(
            new IssuerSerial(
                new GeneralNames(DirectoryName::fromDNString('cn=Issuer')), 42));
        $issuer = AttCertIssuer::fromName(Name::fromString('cn=Issuer'));
        $validity = AttCertValidityPeriod::fromStrings('2016-04-29 12:00:00',
            '2016-04-29 13:00:00');
        $attribs = Attributes::fromAttributeValues(
            new RoleAttributeValue(new UniformResourceIdentifier('urn:admin')));
        $acinfo = new AttributeCertificateInfo($holder, $issuer, $validity,
            $attribs);
        $algo = new SHA256WithRSAEncryptionAlgorithmIdentifier();
        $acinfo = $acinfo->withSignature($algo)->withSerialNumber(1);
        $signature = Crypto::getDefault()->sign(
            $acinfo->toASN1()
                ->toDER(), self::$_privateKeyInfo, $algo);
        $ac = new AttributeCertificate($acinfo, $algo, $signature);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testEncode(AttributeCertificate $ac)
    {
        $seq = $ac->toASN1();
        $this->assertInstanceOf(Sequence::class, $seq);
        return $seq->toDER();
    }

    /**
     * @depends testEncode
     *
     * @param string $der
     */
    public function testDecode($der)
    {
        $ac = AttributeCertificate::fromASN1(Sequence::fromDER($der));
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param AttributeCertificate $ref
     * @param AttributeCertificate $new
     */
    public function testRecoded(AttributeCertificate $ref,
        AttributeCertificate $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testAttributeCertificateInfo(AttributeCertificate $ac)
    {
        $this->assertInstanceOf(AttributeCertificateInfo::class, $ac->acinfo());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testSignatureAlgo(AttributeCertificate $ac)
    {
        $this->assertInstanceOf(SignatureAlgorithmIdentifier::class,
            $ac->signatureAlgorithm());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testSignatureValue(AttributeCertificate $ac)
    {
        $this->assertInstanceOf(Signature::class, $ac->signatureValue());
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testVerify(AttributeCertificate $ac)
    {
        $pubkey_info = self::$_privateKeyInfo->publicKeyInfo();
        $this->assertTrue($ac->verify($pubkey_info));
    }

    /**
     * @depends testCreate
     *
     * @param AttributeCertificate $ac
     */
    public function testInvalidAlgoFail(AttributeCertificate $ac)
    {
        $seq = $ac->toASN1();
        $algo = new GenericAlgorithmIdentifier('1.3.6.1.3');
        $seq = $seq->withReplaced(1, $algo->toASN1());
        $this->expectException(\UnexpectedValueException::class);
        AttributeCertificate::fromASN1($seq);
    }

    public function testFromPEM()
    {
        $ac = AttributeCertificate::fromPEM(self::$_acPem);
        $this->assertInstanceOf(AttributeCertificate::class, $ac);
        return $ac;
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testToPEM(AttributeCertificate $ac)
    {
        $pem = $ac->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testPEMEquals(PEM $pem)
    {
        $this->assertEquals(self::$_acPem, $pem);
    }

    public function testInvalidPEMTypeFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        AttributeCertificate::fromPEM(new PEM('fail', ''));
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testToString(AttributeCertificate $ac)
    {
        $this->assertIsString(strval($ac));
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testIsHeldBy(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ecdsa.pem'));
        $this->assertTrue($ac->isHeldBy($cert));
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testIsHeldByFail(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $this->assertFalse($ac->isHeldBy($cert));
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testIsIssuedBy(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-rsa.pem'));
        $this->assertTrue($ac->isIssuedBy($cert));
    }

    /**
     * @depends testFromPEM
     *
     * @param AttributeCertificate $ac
     */
    public function testIsIssuedByFail(AttributeCertificate $ac)
    {
        $cert = Certificate::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/certs/acme-ca.pem'));
        $this->assertFalse($ac->isIssuedBy($cert));
    }
}
