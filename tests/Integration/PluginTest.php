<?php
/**
 * The plugin inside WordPress: switched off by default, the sign-in flow, break-glass, metadata, logging.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso\Tests;

use Shakewell\SamlSso\Config;
use Shakewell\SamlSso\Plugin;
use WP_UnitTestCase;

/**
 * Settings come from the environment here, as on a server.
 */
final class PluginTest extends WP_UnitTestCase {

	private const KEYS = array( 'ENABLED', 'IDP_ENTITY_ID', 'IDP_SSO_URL', 'IDP_CERTS', 'SP_BASE_URL', 'SP_ENTITY_ID', 'AUTO_CREATE', 'ALLOWED_DOMAINS' );

	/** @var array{priv: string, cert: string} */
	private array $idp;

	private string $log = '';

	public function set_up(): void {
		parent::set_up();
		$this->idp = Fixture::make_idp();
		$this->log = tempnam( sys_get_temp_dir(), 'sso' );
		ini_set( 'error_log', $this->log ); // phpcs:ignore WordPress.PHP.IniSet.Risky
		add_filter( 'send_auth_cookies', '__return_false' );
	}

	public function tear_down(): void {
		foreach ( self::KEYS as $key ) {
			putenv( Config::PREFIX . $key );
		}
		unset( $_POST['SAMLResponse'], $_POST['RelayState'], $_SERVER['REQUEST_METHOD'] );
		$_SERVER['REQUEST_URI'] = '/';
		wp_set_current_user( 0 );
		unlink( $this->log );
		parent::tear_down();
	}

	private function enable( array $extra = array() ): void {
		$env = $extra + array(
			'ENABLED'       => 'true',
			'IDP_ENTITY_ID' => Fixture::IDP,
			'IDP_SSO_URL'   => Fixture::SSO,
			'IDP_CERTS'     => Fixture::pem_body( $this->idp['cert'] ),
			'SP_BASE_URL'   => Fixture::BASE,
			'SP_ENTITY_ID'  => Fixture::SP,
		);
		foreach ( $env as $k => $v ) {
			putenv( Config::PREFIX . $k . '=' . $v );
		}
		Plugin::boot();
	}

	/** Posts a response to the ACS and returns the redirect target, or throws what wp_die throws. */
	private function post( string $response, string $relay = '' ): string {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['REQUEST_URI']    = '/';
		$_POST['SAMLResponse']     = $response;
		$_POST['RelayState']       = $relay;
		add_filter(
			'wp_redirect',
			function ( $location ) {
				throw new \RuntimeException( 'redirect:' . $location );
			}
		);
		try {
			Plugin::acs();
		} catch ( \RuntimeException $e ) {
			return $e->getMessage();
		}
		return 'no redirect';
	}

	private function logged(): string {
		return (string) file_get_contents( $this->log );
	}

	public function test_plugin_boots_on_plugins_loaded(): void {
		$this->assertNotFalse( has_action( 'plugins_loaded', array( Plugin::class, 'boot' ) ) );
	}

	public function test_off_by_default_registers_nothing(): void {
		Plugin::boot();
		$this->assertFalse( has_action( 'init', array( Plugin::class, 'acs' ) ) );
		$this->assertFalse( has_action( 'login_form', array( Plugin::class, 'link' ) ) );
		$this->assertFalse( has_action( 'login_form_' . Plugin::ACTION_METADATA, array( Plugin::class, 'metadata' ) ) );
	}

	public function test_enabled_but_incomplete_stays_inert_and_says_what_is_missing(): void {
		putenv( Config::PREFIX . 'ENABLED=true' );
		Plugin::boot();
		$this->assertFalse( has_action( 'init', array( Plugin::class, 'acs' ) ) );
		$this->assertStringContainsString( 'SHAKEWELL_SAML_SSO_IDP_ENTITY_ID', $this->logged() );
	}

	public function test_enabled_registers_the_endpoints(): void {
		$this->enable();
		$this->assertSame( 1, has_action( 'init', array( Plugin::class, 'acs' ) ) );
		$this->assertNotFalse( has_action( 'login_form_' . Plugin::ACTION_LOGIN, array( Plugin::class, 'login' ) ) );
		$this->assertNotFalse( has_action( 'login_form_' . Plugin::ACTION_METADATA, array( Plugin::class, 'metadata' ) ) );
		$this->assertNotFalse( has_action( 'login_form_' . Plugin::ACTION_SLS, array( Plugin::class, 'sls' ) ) );
		ob_start();
		Plugin::link();
		$this->assertStringContainsString( 'action=' . Plugin::ACTION_LOGIN, ob_get_clean() );
	}

	public function test_valid_signed_response_logs_the_matching_user_in(): void {
		$this->enable();
		$id = self::factory()->user->create(
			array(
				'user_login' => 'jane@example.test',
				'user_email' => 'jane@example.test',
				'role'       => 'editor',
			)
		);
		$to = $this->post( Fixture::response( $this->idp, Fixture::request_id() ), '/wp/wp-admin/edit.php' );
		$this->assertSame( 'redirect:https://sso.example.test/wp/wp-admin/edit.php', $to );
		$this->assertSame( $id, get_current_user_id() );
	}

	public function test_a_refused_response_logs_nobody_in_and_shows_a_plain_page(): void {
		$this->enable();
		self::factory()->user->create(
			array(
				'user_login' => 'jane@example.test',
				'user_email' => 'jane@example.test',
			)
		);
		$other = Fixture::make_idp();
		$this->expectException( \WPDieException::class );
		try {
			$this->post( Fixture::response( $other, Fixture::request_id() ) );
		} finally {
			$this->assertSame( 0, get_current_user_id() );
		}
	}

	public function test_a_post_to_another_path_is_ignored(): void {
		$this->enable();
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['REQUEST_URI']    = '/somewhere-else/';
		$_POST['SAMLResponse']     = 'x';
		Plugin::acs();
		$this->assertSame( '', $this->logged() );
	}

	public function test_break_glass_local_login_still_works_with_sso_on(): void {
		$this->enable();
		self::factory()->user->create(
			array(
				'user_login' => 'localadmin',
				'user_pass'  => 'a-long-local-pass-1',
				'role'       => 'administrator',
			)
		);
		$user = wp_authenticate( 'localadmin', 'a-long-local-pass-1' );
		$this->assertInstanceOf( \WP_User::class, $user );
		$this->assertFalse( has_filter( 'authenticate', array( Plugin::class, 'acs' ) ) );
		$this->assertInstanceOf( \WP_Error::class, wp_authenticate( 'localadmin', 'wrong' ) );
	}

	public function test_metadata_names_the_entity_and_the_acs_and_needs_no_certificate(): void {
		$xml = Plugin::metadata_xml( Fixture::config( array( 'AAAA' ) ) );
		$this->assertStringContainsString( 'entityID="' . Fixture::SP . '"', $xml );
		$this->assertStringContainsString( 'Location="' . Fixture::ACS . '"', $xml );
		$this->assertStringNotContainsString( 'X509Certificate', $xml );
		$this->assertStringContainsString( 'action=' . Plugin::ACTION_SLS, $xml );
	}

	public function test_nothing_personal_reaches_the_log(): void {
		$this->enable( array( 'ALLOWED_DOMAINS' => 'allowed.test' ) );
		self::factory()->user->create(
			array(
				'user_login' => 'jane@example.test',
				'user_email' => 'jane@example.test',
			)
		);
		$attrs = array(
			Config::CLAIM_EMAIL => array( 'jane@example.test' ),
			Config::CLAIM_FIRST => array( 'Jane' ),
			Config::CLAIM_LAST  => array( 'Citizen' ),
			Fixture::OID        => array( 'oid-secret-123' ),
		);
		$other = Fixture::make_idp();
		$cases = array(
			array( $this->idp, array( 'attrs' => $attrs ) ), // Domain not allowed.
			array( $other, array( 'attrs' => $attrs ) ), // Wrong key.
			array( $this->idp, array( 'attrs' => $attrs, 'aud' => 'https://evil.example/' ) ), // phpcs:ignore -- Wrong audience.
			array( $this->idp, array( 'attrs' => $attrs, 'sign' => 'none' ) ), // phpcs:ignore -- Unsigned.
		);
		foreach ( $cases as $case ) {
			try {
				$this->post( Fixture::response( $case[0], Fixture::request_id(), $case[1] + array( 'name' => 'jane@example.test' ) ) );
			} catch ( \WPDieException $e ) {
				$this->addToAssertionCount( 1 );
			}
		}
		$log = $this->logged();
		$this->assertNotSame( '', $log, 'refusals are logged' );
		foreach ( array( 'jane', 'Jane', 'Citizen', 'oid-secret-123' ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $log );
		}
	}
}
