<?php
/**
 * Create an end-entity certificate based on CSR and sign using CA certificate.
 *
 * php issue-cert.php <(php create-ca-cert.php) <(php create-csr.php)
 */

declare(strict_types = 1);

use Sop\CryptoEncoding\PEM;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Hash\SHA512AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature\SignatureAlgorithmIdentifierFactory;
use Webmasterskaya\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Webmasterskaya\X509\Certificate\Certificate;
use Webmasterskaya\X509\Certificate\Extension\BasicConstraintsExtension;
use Webmasterskaya\X509\Certificate\Extension\KeyUsageExtension;
use Webmasterskaya\X509\Certificate\TBSCertificate;
use Webmasterskaya\X509\Certificate\Validity;
use Webmasterskaya\X509\CertificationRequest\CertificationRequest;

require dirname(__DIR__) . '/vendor/autoload.php';

3 == $argc or printf("Usage: %s <ca-path> <csr-path>\n", $argv[0]) and exit(1);
// load issuer certificate from PEM
$issuer_cert = Certificate::fromPEM(PEM::fromFile($argv[1]));
// load certification request from PEM
$csr = CertificationRequest::fromPEM(PEM::fromFile($argv[2]));
// verify CSR
if (!$csr->verify()) {
    echo "Failed to verify certification request signature.\n";
    exit(1);
}
// load CA's private key from PEM
$private_key_info = PrivateKeyInfo::fromPEM(
    PEM::fromFile(dirname(__DIR__) . '/test/assets/rsa/private_key.pem'));
// initialize certificate from CSR and issuer's certificate
$tbs_cert = TBSCertificate::fromCSR($csr)->withIssuerCertificate($issuer_cert);
// set random serial number
$tbs_cert = $tbs_cert->withRandomSerialNumber();
// set validity period
$tbs_cert = $tbs_cert->withValidity(
    Validity::fromStrings('now', 'now + 3 months'));
// add extensions
$tbs_cert = $tbs_cert->withAdditionalExtensions(
    new KeyUsageExtension(true,
        KeyUsageExtension::DIGITAL_SIGNATURE |
             KeyUsageExtension::KEY_ENCIPHERMENT),
    new BasicConstraintsExtension(true, false));
// sign certificate with issuer's private key
$algo = SignatureAlgorithmIdentifierFactory::algoForAsymmetricCrypto(
    $private_key_info->algorithmIdentifier(), new SHA512AlgorithmIdentifier());
$cert = $tbs_cert->sign($algo, $private_key_info);
echo $cert;
