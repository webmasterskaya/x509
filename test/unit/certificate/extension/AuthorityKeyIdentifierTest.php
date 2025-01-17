<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\Asymmetric\PublicKeyInfo;
use Webmasterskaya\X501\ASN1\Name;
use Webmasterskaya\X509\Certificate\Extension\AuthorityKeyIdentifierExtension;
use Webmasterskaya\X509\Certificate\Extension\Extension;
use Webmasterskaya\X509\Certificate\Extensions;
use Webmasterskaya\X509\GeneralName\DirectoryName;
use Webmasterskaya\X509\GeneralName\GeneralNames;

/**
 * @group certificate
 * @group extension
 *
 * @internal
 */
class AuthorityKeyIdentifierTest extends TestCase
{
    const KEY_ID = 'test-id';

    const SERIAL = 42;

    private static $_issuer;

    public static function setUpBeforeClass(): void
    {
        self::$_issuer = new GeneralNames(
            new DirectoryName(Name::fromString('cn=Issuer')));
    }

    public static function tearDownAfterClass(): void
    {
        self::$_issuer = null;
    }

    public function testCreate()
    {
        $ext = new AuthorityKeyIdentifierExtension(true, self::KEY_ID,
            self::$_issuer, self::SERIAL);
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    public function testFromPKI()
    {
        $pki = PublicKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . '/rsa/public_key.pem'));
        $ext = AuthorityKeyIdentifierExtension::fromPublicKeyInfo($pki);
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testOID(Extension $ext)
    {
        $this->assertEquals(Extension::OID_AUTHORITY_KEY_IDENTIFIER, $ext->oid());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testCritical(Extension $ext)
    {
        $this->assertTrue($ext->isCritical());
    }

    /**
     * @depends testCreate
     *
     * @param Extension $ext
     */
    public function testEncode(Extension $ext)
    {
        $seq = $ext->toASN1();
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
        $ext = AuthorityKeyIdentifierExtension::fromASN1(
            Sequence::fromDER($der));
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Extension $ref
     * @param Extension $new
     */
    public function testRecoded(Extension $ref, Extension $new)
    {
        $this->assertEquals($ref, $new);
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityKeyIdentifierExtension $ext
     */
    public function testKeyIdentifier(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::KEY_ID, $ext->keyIdentifier());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityKeyIdentifierExtension $ext
     */
    public function testIssuer(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::$_issuer, $ext->issuer());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityKeyIdentifierExtension $ext
     */
    public function testSerial(AuthorityKeyIdentifierExtension $ext)
    {
        $this->assertEquals(self::SERIAL, $ext->serial());
    }

    /**
     * @depends testCreate
     *
     * @param AuthorityKeyIdentifierExtension $ext
     */
    public function testExtensions(AuthorityKeyIdentifierExtension $ext)
    {
        $extensions = new Extensions($ext);
        $this->assertTrue($extensions->hasAuthorityKeyIdentifier());
        return $extensions;
    }

    /**
     * @depends testExtensions
     *
     * @param Extensions $exts
     */
    public function testFromExtensions(Extensions $exts)
    {
        $ext = $exts->authorityKeyIdentifier();
        $this->assertInstanceOf(AuthorityKeyIdentifierExtension::class, $ext);
    }

    public function testDecodeIssuerXorSerialFail()
    {
        $seq = new Sequence(new ImplicitlyTaggedType(0, new OctetString('')),
            new ImplicitlyTaggedType(2, new Integer(1)));
        $ext_seq = new Sequence(
            new ObjectIdentifier(Extension::OID_AUTHORITY_KEY_IDENTIFIER),
            new OctetString($seq->toDER()));
        $this->expectException(\UnexpectedValueException::class);
        AuthorityKeyIdentifierExtension::fromASN1($ext_seq);
    }

    public function testEncodeIssuerXorSerialFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, '', null, 1);
        $this->expectException(\LogicException::class);
        $ext->toASN1();
    }

    public function testNoKeyIdentifierFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(\LogicException::class);
        $ext->keyIdentifier();
    }

    public function testNoIssuerFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(\LogicException::class);
        $ext->issuer();
    }

    public function testNoSerialFail()
    {
        $ext = new AuthorityKeyIdentifierExtension(false, null);
        $this->expectException(\LogicException::class);
        $ext->serial();
    }
}
