<?php
/**
 * Test identity provider: signs SAML responses with a throwaway key made at run time. No key is committed.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso\Tests;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Shakewell\SamlSso\Acs;
use Shakewell\SamlSso\Config;

/**
 * Builders shared by the tests.
 */
final class Fixture {

	public const BASE = 'https://sso.example.test';
	public const SP   = 'https://sso.example.test/sp';
	public const ACS  = 'https://sso.example.test/';
	public const IDP  = 'https://sts.example.test/tenant-id/';
	public const SSO  = 'https://login.example.test/tenant-id/saml2';
	public const OID  = 'http://schemas.microsoft.com/identity/claims/objectidentifier';

	/**
	 * A fresh key and self-signed certificate.
	 *
	 * @return array{priv: string, cert: string}
	 */
	public static function make_idp(): array {
		$key = openssl_pkey_new(
			array(
				'private_key_bits' => 2048,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			)
		);
		$csr = openssl_csr_new( array( 'commonName' => 'test-idp' ), $key );
		openssl_x509_export( openssl_csr_sign( $csr, null, $key, 2 ), $cert );
		openssl_pkey_export( $key, $priv );
		return array(
			'priv' => $priv,
			'cert' => $cert,
		);
	}

	/**
	 * Certificate body: base64 without the PEM header.
	 *
	 * @param string $pem Certificate.
	 */
	public static function pem_body( string $pem ): string {
		return preg_replace( '/-----[A-Z ]+-----|\s+/', '', $pem );
	}

	/**
	 * Time as the XML wants it.
	 *
	 * @param int $t Unix time.
	 */
	public static function xml_time( int $t ): string {
		return gmdate( 'Y-m-d\TH:i:s\Z', $t );
	}

	/**
	 * Settings for a site that trusts the given certificates.
	 *
	 * @param string[]            $certs Certificate bodies.
	 * @param array<string,mixed> $env    Extra or overriding settings.
	 */
	public static function config( array $certs, array $env = array() ): Config {
		$env += array(
			'IDP_ENTITY_ID' => self::IDP,
			'IDP_SSO_URL'   => self::SSO,
			'IDP_CERTS'     => implode( ',', $certs ),
			'SP_BASE_URL'   => self::BASE,
			'SP_ENTITY_ID'  => self::SP,
		);
		return new Config( $env, self::BASE . '/', self::BASE . '/wp/wp-login.php' );
	}

	/**
	 * A consumer for the given certificates.
	 *
	 * @param string[]            $certs Certificate bodies.
	 * @param array<string,mixed> $env    Extra or overriding settings.
	 */
	public static function acs( array $certs, array $env = array() ): Acs {
		return new Acs( self::config( $certs, $env ) );
	}

	/**
	 * Registers a request id as one this site started.
	 */
	public static function request_id(): string {
		$id = '_req' . bin2hex( random_bytes( 8 ) );
		set_transient( 'shakewell_saml_sso_req_' . hash( 'sha256', $id ), 1, 600 );
		return $id;
	}

	/**
	 * Builds a base64 response. Options override any default. 'sign' is assertion, response or none; 'mutate' edits the DOM after signing.
	 *
	 * @param array{priv: string, cert: string} $idp    Key pair to sign with.
	 * @param string                            $req_id Request id the response answers.
	 * @param array<string,mixed>               $o      Options.
	 */
	public static function response( array $idp, string $req_id, array $o = array() ): string {
		$o    += array(
			'id'        => '_a' . bin2hex( random_bytes( 8 ) ),
			'issuer'    => self::IDP,
			'aud'       => self::SP,
			'dest'      => self::ACS,
			'recipient' => self::ACS,
			'name'      => 'jane@example.test',
			'nb'        => time() - 30,
			'noa'       => time() + 300,
			'sign'      => 'assertion',
			'attrs'     => array(
				Config::CLAIM_EMAIL => array( 'jane@example.test' ),
				self::OID           => array( 'oid-jane' ),
			),
		);
		$attrs = '';
		foreach ( $o['attrs'] as $n => $vals ) {
			$attrs .= '<saml:Attribute Name="' . htmlspecialchars( $n ) . '">'
				. implode( '', array_map( fn( $v ) => '<saml:AttributeValue>' . htmlspecialchars( $v ) . '</saml:AttributeValue>', $vals ) )
				. '</saml:Attribute>';
		}
		$xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r' . bin2hex( random_bytes( 6 ) ) . '" Version="2.0" IssueInstant="' . self::xml_time( time() ) . '" Destination="' . $o['dest'] . '" InResponseTo="' . $req_id . '">'
			. '<saml:Issuer>' . $o['issuer'] . '</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
			. '<saml:Assertion ID="' . $o['id'] . '" Version="2.0" IssueInstant="' . self::xml_time( time() ) . '"><saml:Issuer>' . $o['issuer'] . '</saml:Issuer>'
			. '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' . $o['name'] . '</saml:NameID>'
			. '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="' . $req_id . '" NotOnOrAfter="' . self::xml_time( $o['noa'] ) . '" Recipient="' . $o['recipient'] . '"/></saml:SubjectConfirmation></saml:Subject>'
			. '<saml:Conditions NotBefore="' . self::xml_time( $o['nb'] ) . '" NotOnOrAfter="' . self::xml_time( $o['noa'] ) . '"><saml:AudienceRestriction><saml:Audience>' . $o['aud'] . '</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
			. '<saml:AuthnStatement AuthnInstant="' . self::xml_time( time() ) . '" SessionIndex="_sess1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
			. '<saml:AttributeStatement>' . $attrs . '</saml:AttributeStatement></saml:Assertion></samlp:Response>';
		$doc = new \DOMDocument();
		$doc->loadXML( $xml );
		if ( 'none' !== $o['sign'] ) {
			$xp = new \DOMXPath( $doc );
			$xp->registerNamespace( 's', 'urn:oasis:names:tc:SAML:2.0:assertion' );
			$assertion = 'assertion' === $o['sign'];
			$node      = $assertion ? $xp->query( '//s:Assertion' )->item( 0 ) : $doc->documentElement;
			$before    = $assertion ? $xp->query( '//s:Assertion/s:Subject' )->item( 0 ) : $xp->query( '/*/s:Issuer' )->item( 0 )->nextSibling;
			$dsig      = new XMLSecurityDSig();
			$dsig->setCanonicalMethod( XMLSecurityDSig::EXC_C14N );
			$dsig->addReference(
				$node,
				XMLSecurityDSig::SHA256,
				array( 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N ),
				array(
					'id_name'   => 'ID',
					'overwrite' => false,
				)
			);
			$k = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, array( 'type' => 'private' ) );
			$k->loadKey( $idp['priv'] );
			$dsig->sign( $k );
			$dsig->add509Cert( $idp['cert'] );
			$dsig->insertSignature( $node, $before );
		}
		if ( isset( $o['mutate'] ) ) {
			( $o['mutate'] )( $doc );
		}
		return base64_encode( $doc->saveXML() ); // phpcs:ignore
	}
}
