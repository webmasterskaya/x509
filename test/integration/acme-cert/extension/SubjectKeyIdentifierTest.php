<?php

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use Webmasterskaya\X509\Certificate\Extension\Extension;
use Webmasterskaya\X509\Certificate\Extension\SubjectKeyIdentifierExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefSubjectKeyIdentifierTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return SubjectKeyIdentifierExtension
     */
    public function testSubjectKeyIdentifier()
    {
        $ext = self::$_extensions->get(Extension::OID_SUBJECT_KEY_IDENTIFIER);
        $this->assertInstanceOf(SubjectKeyIdentifierExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testSubjectKeyIdentifier
     *
     * @param SubjectKeyIdentifierExtension $ski
     */
    public function testSubjectKeyIdentifierKey(
        SubjectKeyIdentifierExtension $ski)
    {
        $pem = PEM::fromFile(TEST_ASSETS_DIR . '/certs/keys/acme-rsa.pem');
        $keyid = RSAPrivateKey::fromPEM($pem)->publicKey()
            ->publicKeyInfo()
            ->keyIdentifier();
        $this->assertEquals($keyid, $ski->keyIdentifier());
    }
}
