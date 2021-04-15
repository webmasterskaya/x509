<?php
/**
 * Create certification authority certificate.
 *
 * php create-ca-cert.php
 */

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA256AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Webmasterskaya\X501\ASN1\Name;
use Webmasterskaya\X509\Certificate\Extension\BasicConstraintsExtension;
use Webmasterskaya\X509\Certificate\Extension\KeyUsageExtension;
use Webmasterskaya\X509\Certificate\Extension\SubjectKeyIdentifierExtension;
use Webmasterskaya\X509\Certificate\TBSCertificate;
use Webmasterskaya\X509\Certificate\Validity;

require dirname(__DIR__) . '/vendor/autoload.php';

// load RSA private key from PEM
$private_key_info = PrivateKeyInfo::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/test/assets/rsa/private_key.pem'));
// extract public key from private key
$public_key_info = $private_key_info->publicKeyInfo();
// DN of the certification authority
$name = Name::fromString('cn=Example CA');
// validity period
$validity = Validity::fromStrings('now', 'now + 10 years');
// create "to be signed" certificate object with extensions
$tbs_cert = new TBSCertificate($name, $public_key_info, $name, $validity);
$tbs_cert = $tbs_cert->withRandomSerialNumber()->withAdditionalExtensions(
    new BasicConstraintsExtension(true, true),
    new SubjectKeyIdentifierExtension(false, $public_key_info->keyIdentifier()),
    new KeyUsageExtension(true,
        KeyUsageExtension::DIGITAL_SIGNATURE | KeyUsageExtension::KEY_CERT_SIGN));
// sign certificate with private key
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $private_key_info->algorithmIdentifier(), new SHA256AlgorithmIdentifier());
$cert = $tbs_cert->sign($algo, $private_key_info);
echo $cert;
