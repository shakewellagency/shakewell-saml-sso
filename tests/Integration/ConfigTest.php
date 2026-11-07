<?php
/**
 * Settings.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso\Tests;

use Shakewell\SamlSso\Config;
use Shakewell\SamlSso\Plugin;
use WP_UnitTestCase;

/**
 * Parsing, defaults, the setting names and the library settings.
 */
final class ConfigTest extends WP_UnitTestCase {

	private const HOME  = 'https://sso.example.test/';
	private const LOGIN = 'https://sso.example.test/wp/wp-login.php';

	public function tear_down(): void {
		foreach ( array( 'SHAKEWELL_SAML_SSO_IDP_SSO_URL', 'SAML_IDP_SSO_URL', 'SHAKEWELL_SAML_SSO_AUTO_CREATE', 'SHAKEWELL_SAML_SSO_GROUP_CLAIM' ) as $name ) {
			putenv( $name );
		}
		parent::tear_down();
	}

	private function config( array $env ): Config {
		return new Config( $env, self::HOME, self::LOGIN );
	}

	public function test_off_by_default(): void {
		$this->assertFalse( $this->config( array() )->enabled() );
		$this->assertFalse( Config::from_environment( self::HOME, self::LOGIN )->enabled() );
	}

	public function test_two_pem_blocks_are_parsed_and_arrays_are_accepted(): void {
		$pem = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----";
		$this->assertSame( array( 'AAAABBBB', 'CCCC' ), $this->config( array( 'IDP_CERTS' => $pem ) )->idp_certs() );
		$this->assertSame( array( 'AAAA', 'BBBB', 'CCCC' ), $this->config( array( 'IDP_CERTS' => 'AAAA, BBBB,CCCC,AAAA' ) )->idp_certs() );
		$this->assertSame( array( 'AAAA', 'BBBB', 'CCCC' ), $this->config( array( 'IDP_CERTS' => array( 'AAAA', "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----", 'CCCC' ) ) )->idp_certs() );
		$this->assertSame( array(), $this->config( array( 'IDP_CERTS' => 'not base64 !!' ) )->idp_certs() );
	}

	public function test_missing_settings_are_named(): void {
		$this->assertSame(
			array( 'SHAKEWELL_SAML_SSO_IDP_ENTITY_ID', 'SHAKEWELL_SAML_SSO_IDP_SSO_URL', 'SHAKEWELL_SAML_SSO_IDP_CERTS' ),
			$this->config( array( 'ENABLED' => 'true' ) )->missing()
		);
		$this->assertSame( array(), $this->config( array( 'IDP_ENTITY_ID' => 'x', 'IDP_SSO_URL' => 'https://x/', 'IDP_CERTS' => 'AAAA' ) )->missing() ); // phpcs:ignore
	}

	public function test_defaults_are_the_site_and_the_safe_choices(): void {
		$c = $this->config( array() );
		$this->assertSame( 'https://sso.example.test', $c->base_url() );
		$this->assertSame( 'https://sso.example.test', $c->entity_id() );
		$this->assertSame( 'https://sso.example.test/', $c->acs_url() );
		$this->assertFalse( $c->auto_create() );
		$this->assertSame( 'subscriber', $c->default_role() );
		$this->assertSame( 'assertion', $c->signed_element() );
		$this->assertSame( array(), $c->allowed_domains() );
		$this->assertSame( array( 'sso.example.test' ), $c->allowed_hosts() );
		$this->assertSame( Config::CLAIM_EMAIL, $c->email_attr() );
	}

	public function test_strict_settings_and_no_sp_certificate_needed(): void {
		$s = Fixture::config( array( 'AAAA' ) )->settings();
		$this->assertTrue( $s['strict'] );
		$this->assertTrue( $s['security']['wantAssertionsSigned'] );
		$this->assertTrue( $s['security']['rejectUnsolicitedResponsesWithInResponseTo'] );
		$this->assertTrue( $s['security']['destinationStrictlyMatches'] );
		$this->assertFalse( $s['security']['wantAssertionsEncrypted'] );
		$this->assertFalse( $s['security']['authnRequestsSigned'] ?? false, 'requests are not signed' );
		$this->assertSame( '', $s['sp']['x509cert'] );
		$this->assertSame( Fixture::SP, $s['sp']['entityId'] );
		$this->assertSame( Fixture::ACS, $s['sp']['assertionConsumerService']['url'] );
		$r = Fixture::config( array( 'AAAA' ), array( 'SIGNED_ELEMENT' => 'response' ) )->settings();
		$this->assertTrue( $r['security']['wantMessagesSigned'] );
		$this->assertFalse( $r['security']['wantAssertionsSigned'] );
	}

	public function test_prefixed_names_are_read_from_the_environment_and_unprefixed_ones_are_ignored(): void {
		putenv( 'SAML_IDP_SSO_URL=https://unprefixed.example/' );
		$this->assertStringNotContainsString( 'unprefixed.example', Config::from_environment( self::HOME, self::LOGIN )->settings()['idp']['singleSignOnService']['url'] );
		putenv( 'SHAKEWELL_SAML_SSO_IDP_SSO_URL=https://prefixed.example/' );
		$this->assertStringContainsString( 'prefixed.example', Config::from_environment( self::HOME, self::LOGIN )->settings()['idp']['singleSignOnService']['url'] );
	}

	/**
	 * Constants cannot be undefined, so this runs in its own process to keep them from leaking into other tests.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_constants_are_read_and_win_over_the_environment(): void {
		putenv( 'SHAKEWELL_SAML_SSO_GROUP_CLAIM=from-env' );
		define( 'SHAKEWELL_SAML_SSO_GROUP_CLAIM', 'from-constant' );
		define( 'SHAKEWELL_SAML_SSO_AUTO_CREATE', false );
		putenv( 'SHAKEWELL_SAML_SSO_AUTO_CREATE=true' );
		$c = Config::from_environment( self::HOME, self::LOGIN );
		$this->assertSame( 'from-constant', $c->group_claim() );
		$this->assertFalse( $c->auto_create(), 'a constant set to false is honoured, not skipped' );
	}

	public function test_sign_out_url_names_our_action(): void {
		$this->assertStringEndsWith( '?action=' . Plugin::ACTION_SLS, $this->config( array() )->slo_url() );
	}
}
