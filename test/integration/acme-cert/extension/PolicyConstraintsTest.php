<?php

declare(strict_types = 1);

use Webmasterskaya\X509\Certificate\Extension\Extension;
use Webmasterskaya\X509\Certificate\Extension\PolicyConstraintsExtension;

require_once __DIR__ . '/RefExtTestHelper.php';

/**
 * @group certificate
 * @group extension
 * @group decode
 *
 * @internal
 */
class RefPolicyConstraintsTest extends RefExtTestHelper
{
    /**
     * @param Extensions $extensions
     *
     * @return PolicyConstraintsExtension
     */
    public function testPolicyConstraintsExtension()
    {
        $ext = self::$_extensions->get(Extension::OID_POLICY_CONSTRAINTS);
        $this->assertInstanceOf(PolicyConstraintsExtension::class, $ext);
        return $ext;
    }

    /**
     * @depends testPolicyConstraintsExtension
     *
     * @param PolicyConstraintsExtension $pc
     */
    public function testRequireExplicitPolicy(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(3, $pc->requireExplicitPolicy());
    }

    /**
     * @depends testPolicyConstraintsExtension
     *
     * @param PolicyConstraintsExtension $pc
     */
    public function testInhibitPolicyMapping(PolicyConstraintsExtension $pc)
    {
        $this->assertEquals(1, $pc->inhibitPolicyMapping());
    }
}
