<?php

namespace X509\Certificate\Extension;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;
use X509\Certificate\Extension\CertificatePolicy\PolicyInformation;


/**
 * Implements 'Certificate Policies' certificate extension.
 *
 * @link https://tools.ietf.org/html/rfc5280#section-4.2.1.4
 */
class CertificatePoliciesExtension extends Extension implements 
	\Countable, 
	\IteratorAggregate
{
	/**
	 * Policy information terms.
	 *
	 * @var PolicyInformation[] $_policies
	 */
	protected $_policies;
	
	/**
	 * Constructor
	 *
	 * @param bool $critical
	 * @param PolicyInformation ...$policies
	 */
	public function __construct($critical, PolicyInformation ...$policies) {
		parent::__construct(Extension::OID_CERTIFICATE_POLICIES, $critical);
		$this->_policies = array();
		foreach ($policies as $policy) {
			$this->_policies[$policy->oid()] = $policy;
		}
	}
	
	protected static function _fromDER($data, $critical) {
		$policies = array_map(
			function (UnspecifiedType $el) {
				return PolicyInformation::fromASN1($el->asSequence());
			}, Sequence::fromDER($data)->elements());
		if (!count($policies)) {
			throw new \UnexpectedValueException(
				"certificatePolicies must contain" .
					 " at least one PolicyInformation.");
		}
		return new self($critical, ...$policies);
	}
	
	/**
	 * Check whether policy information by OID is present.
	 *
	 * @param string $oid
	 * @return boolean
	 */
	public function has($oid) {
		return isset($this->_policies[$oid]);
	}
	
	/**
	 * Check whether anyPolicy is present.
	 *
	 * @return bool
	 */
	public function hasAnyPolicy() {
		return isset($this->_policies[PolicyInformation::OID_ANY_POLICY]);
	}
	
	/**
	 * Get policy information by OID.
	 *
	 * @param string $oid
	 * @throws \LogicException
	 * @return PolicyInformation
	 */
	public function get($oid) {
		if (!$this->has($oid)) {
			throw new \LogicException("Not certificate policy by OID $oid.");
		}
		return $this->_policies[$oid];
	}
	
	protected function _valueASN1() {
		if (!count($this->_policies)) {
			throw new \LogicException("No policies.");
		}
		$elements = array_map(
			function (PolicyInformation $pi) {
				return $pi->toASN1();
			}, array_values($this->_policies));
		return new Sequence(...$elements);
	}
	
	/**
	 * Get the number of policies.
	 *
	 * @see Countable::count()
	 * @return int
	 */
	public function count() {
		return count($this->_policies);
	}
	
	/**
	 * Get iterator for policy information terms.
	 *
	 * @see IteratorAggregate::getIterator()
	 * @return \ArrayIterator
	 */
	public function getIterator() {
		return new \ArrayIterator($this->_policies);
	}
}
