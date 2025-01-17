<?php

declare(strict_types = 1);

use Webmasterskaya\X501\ASN1\AttributeType;
use Webmasterskaya\X509\Certificate\Extension\Extension;
use Webmasterskaya\X509\Certificate\Extension\SubjectDirectoryAttributesExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefSubjectDirectoryAttributesTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return SubjectDirectoryAttributesExtension
     */
    public function testSubjectDirectoryAttributesExtension()
    {
        $ext = self::$_extensions->get(
            Extension::OID_SUBJECT_DIRECTORY_ATTRIBUTES);
        $this->assertInstanceOf(SubjectDirectoryAttributesExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testSubjectDirectoryAttributesExtension
     *
     * @param SubjectDirectoryAttributesExtension $sda
     */
    public function testSDADescription(SubjectDirectoryAttributesExtension $sda)
    {
        $desc = $sda->firstOf(AttributeType::OID_DESCRIPTION)
            ->first()
            ->stringValue();
        $this->assertEquals('A Company Manufacturing Everything', $desc);
    }
}
