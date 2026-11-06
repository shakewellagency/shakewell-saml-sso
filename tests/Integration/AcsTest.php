<?php
/**
 * What a response must contain to sign someone in, and what is refused.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso\Tests;

use Shakewell\SamlSso\Config;
use Shakewell\SamlSso\Refused;
use WP_UnitTestCase;

/**
 * Responses are signed in the test with a throwaway key; WordPress users and transients are real.
 */
final class AcsTest extends WP_UnitTestCase {

	private const FALLBACK = 'https://sso.example.test/wp/wp-admin/';

	/** @var array{priv: string, cert: string} */
	private array $idp;

	/** @var array{priv: string, cert: string} */
	private array $old;

	/** @var array{priv: string, cert: string} */
	private array $other;

	public function set_up(): void {
		parent::set_up();
		$this->idp   = Fixture::make_idp();
		$this->old   = Fixture::make_idp();
		$this->other = Fixture::make_idp();
	}

	private function certs(): array {
		return array( Fixture::pem_body( $this->idp['cert'] ) );
	}

	private function go( string $response, string $relay = '', array $env = array() ): array {
		return Fixture::acs( $this->certs(), $env )->consume( $response, $relay, self::FALLBACK );
	}

	private function signed( array $o = array(), ?array $idp = null ): string {
		return Fixture::response( $idp ?? $this->idp, Fixture::request_id(), $o );
	}

	private function jane( string $role = 'editor' ): int {
		return self::factory()->user->create(
			array(
				'user_login' => 'jane@example.test',
				'user_email' => 'jane@example.test',
				'role'       => $role,
			)
		);
	}

	private function assert_refused( callable $f, string $why ): void {
		try {
			$f();
		} catch ( Refused $e ) {
			$this->addToAssertionCount( 1 );
			return;
		}
		$this->fail( 'accepted: ' . $why );
	}

	public function test_valid_signed_response_signs_the_matching_user_in(): void {
		$id = $this->jane();
		$r  = $this->go( $this->signed(), '/wp/wp-admin/edit.php' );
		$this->assertSame( $id, $r['user']->ID );
		$this->assertSame( array( 'editor' ), $r['user']->roles, 'role of an existing user is untouched' );
		$this->assertSame( 'oid-jane', get_user_meta( $id, 'shakewell_saml_sso_id', true ) );
		$this->assertSame( 'https://sso.example.test/wp/wp-admin/edit.php', $r['redirect'] );
		$this->assertSame( '_sess1', $r['sessionIndex'] );
	}

	public function test_falls_back_to_email_when_the_login_differs(): void {
		$id = self::factory()->user->create(
			array(
				'user_login' => 'jsmith',
				'user_email' => 'Jane@Example.test',
			)
		);
		$this->assertSame( $id, $this->go( $this->signed() )['user']->ID );
	}

	public function test_audience_destination_recipient_and_issuer_must_match(): void {
		$this->jane();
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'aud' => 'https://evil.example/' ) ) ), 'wrong audience' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'dest' => 'https://evil.example/' ) ) ), 'wrong destination' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'recipient' => 'https://evil.example/' ) ) ), 'wrong recipient' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'issuer' => 'https://evil.example/idp' ) ) ), 'wrong issuer' );
	}

	public function test_timing_is_enforced_with_a_tight_clock(): void {
		$this->jane();
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'nb' => time() - 7200, 'noa' => time() - 3600 ) ) ), 'expired long ago' ); // phpcs:ignore
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'nb' => time() - 600, 'noa' => time() - 120 ) ) ), 'expired inside the library drift' ); // phpcs:ignore
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'nb' => time() + 3600, 'noa' => time() + 7200 ) ) ), 'not yet valid' ); // phpcs:ignore
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'nb' => time() + 120, 'noa' => time() + 900 ) ) ), 'not yet valid inside the library drift' ); // phpcs:ignore
	}

	public function test_signature_rules(): void {
		$this->jane();
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'sign' => 'none' ) ) ), 'unsigned' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'sign' => 'response' ) ) ), 'only the envelope signed, assertion not' );
		$this->assert_refused( fn() => $this->go( $this->signed( array(), $this->other ) ), 'signed by an unknown key (wrongly signed)' );
		$this->assert_refused(
			fn() => $this->go(
				$this->signed(
					array(
						'mutate' => function ( \DOMDocument $d ) {
							$d->getElementsByTagNameNS( 'urn:oasis:names:tc:SAML:2.0:assertion', 'NameID' )->item( 0 )->nodeValue = 'admin@example.test';
						},
					)
				)
			),
			'body altered after signing'
		);
	}

	public function test_signature_wrapping_is_refused(): void {
		$this->jane();
		$ns = 'urn:oasis:names:tc:SAML:2.0:assertion';
		$this->assert_refused(
			fn() => $this->go(
				$this->signed(
					array(
						'mutate' => function ( \DOMDocument $d ) use ( $ns ) {
							$a    = $d->getElementsByTagNameNS( $ns, 'Assertion' )->item( 0 );
							$evil = $a->cloneNode( true );
							$evil->setAttribute( 'ID', '_evil' );
							foreach ( iterator_to_array( $evil->childNodes ) as $c ) {
								if ( 'Signature' === $c->localName ) {
									$evil->removeChild( $c );
								}
							}
							$evil->getElementsByTagNameNS( $ns, 'NameID' )->item( 0 )->nodeValue = 'admin@example.test';
							$a->parentNode->insertBefore( $evil, $a );
						},
					)
				)
			),
			'unsigned copy for another user placed first'
		);
		$this->assert_refused(
			fn() => $this->go(
				$this->signed(
					array(
						'mutate' => function ( \DOMDocument $d ) use ( $ns ) {
							$a    = $d->getElementsByTagNameNS( $ns, 'Assertion' )->item( 0 );
							$ext  = $d->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Extensions' );
							$evil = $a->cloneNode( true );
							$evil->setAttribute( 'ID', '_evil2' );
							foreach ( iterator_to_array( $evil->childNodes ) as $c ) {
								if ( 'Signature' === $c->localName ) {
									$evil->removeChild( $c );
								}
							}
							$evil->getElementsByTagNameNS( $ns, 'NameID' )->item( 0 )->nodeValue = 'admin@example.test';
							$a->parentNode->replaceChild( $evil, $a );
							$ext->appendChild( $a );
							$evil->parentNode->insertBefore( $ext, $evil );
						},
					)
				)
			),
			'signed assertion moved into an Extensions wrapper'
		);
	}

	public function test_only_responses_to_our_own_requests_are_accepted(): void {
		$this->jane();
		$this->assert_refused( fn() => $this->go( Fixture::response( $this->idp, '' ) ), 'no InResponseTo (unsolicited)' );
		$this->assert_refused( fn() => $this->go( Fixture::response( $this->idp, '_neverissued' ) ), 'request id we never issued' );
	}

	public function test_malformed_input_is_refused(): void {
		$this->assert_refused( fn() => $this->go( base64_encode( '<not-saml/>' ) ), 'garbage' ); // phpcs:ignore
		$this->assert_refused( fn() => $this->go( '%%%' ), 'not base64' );
		$this->assert_refused( fn() => $this->go( '' ), 'empty' );
		$this->assert_refused( fn() => $this->go( base64_encode( '<!DOCTYPE x [<!ENTITY a "b">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_x">&a;</samlp:Response>' ) ), 'DOCTYPE entity' ); // phpcs:ignore
		$this->assert_refused( fn() => $this->go( str_repeat( 'A', 600000 ) ), 'oversized' );
	}

	public function test_a_response_and_an_assertion_work_once(): void {
		$this->jane();
		$resp = $this->signed();
		$this->go( $resp );
		$this->assert_refused( fn() => $this->go( $resp ), 'same response posted twice' );
		// The same assertion id under a fresh request id: the replay store, not the request binding, has to stop it.
		$this->go( $this->signed( array( 'id' => '_replayme' ) ) );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'id' => '_replayme' ) ) ), 'replayed assertion id under a new request' );
	}

	public function test_provider_id_of_another_person_is_refused(): void {
		$this->jane();
		$this->go( $this->signed() );
		$this->assert_refused(
			fn() => $this->go(
				$this->signed(
					array(
						'attrs' => array(
							Config::CLAIM_EMAIL => array( 'jane@example.test' ),
							Fixture::OID        => array( 'someone-else' ),
						),
					)
				)
			),
			'object id of another person on the account'
		);
	}

	public function test_unknown_user_is_refused_unless_creation_is_on(): void {
		$this->assert_refused( fn() => $this->go( $this->signed() ), 'default: no auto-create' );
		$this->assert_refused( fn() => $this->go( $this->signed(), '', array( 'AUTO_CREATE' => 'false' ) ), 'creation off' );
		$this->assertFalse( get_user_by( 'login', 'jane@example.test' ) );
	}

	private function create_with( array $env, array $attrs = array(), string $name = 'new.person@example.test' ): \WP_User {
		$attrs += array( Config::CLAIM_EMAIL => array( 'new.person@example.test' ) );
		return $this->go( $this->signed( array( 'name' => $name, 'attrs' => $attrs ) ), '', $env + array( 'AUTO_CREATE' => 'true' ) )['user']; // phpcs:ignore
	}

	public function test_new_user_gets_the_default_role(): void {
		$u = $this->create_with( array(), array( Config::CLAIM_GROUPS => array( 'g-unmapped' ) ) );
		$this->assertSame( array( 'subscriber' ), $u->roles );
		$this->assertSame( 'new.person@example.test', $u->user_login );
		$u2 = $this->create_with( array( 'DEFAULT_ROLE' => 'author' ), array( Config::CLAIM_EMAIL => array( 'second@example.test' ) ), 'second@example.test' );
		$this->assertSame( array( 'author' ), $u2->roles );
	}

	public function test_group_maps_to_a_role(): void {
		$u = $this->create_with(
			array( 'ROLE_MAP' => '{"g-editors":"editor","g-admins":"administrator"}' ),
			array( Config::CLAIM_GROUPS => array( 'g-x', 'g-editors' ) )
		);
		$this->assertSame( array( 'editor' ), $u->roles );
	}

	public function test_an_administrator_is_never_created_and_roles_must_exist(): void {
		$this->assert_refused( fn() => $this->create_with( array( 'ROLE_MAP' => array( 'g-admins' => 'administrator' ) ), array( Config::CLAIM_GROUPS => array( 'g-admins' ) ) ), 'group mapped to administrator' );
		$this->assert_refused( fn() => $this->create_with( array( 'DEFAULT_ROLE' => 'administrator' ) ), 'default role administrator' );
		$this->assert_refused( fn() => $this->create_with( array( 'DEFAULT_ROLE' => 'no_such_role' ) ), 'role that does not exist' );
	}

	public function test_a_new_user_needs_an_email_and_creation_failure_is_a_refusal(): void {
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'name' => 'new.person@example.test', 'attrs' => array( Config::CLAIM_FIRST => array( 'New' ) ) ) ), '', array( 'AUTO_CREATE' => 'true' ) ), 'no email' ); // phpcs:ignore
		add_filter( 'pre_user_login', '__return_empty_string' );
		$this->assert_refused( fn() => $this->create_with( array() ), 'wp_insert_user failing' );
	}

	public function test_existing_administrator_keeps_the_role_whatever_the_groups_say(): void {
		$id = $this->jane( 'administrator' );
		$r  = $this->go( $this->signed( array( 'attrs' => array( Config::CLAIM_EMAIL => array( 'jane@example.test' ), Config::CLAIM_GROUPS => array( 'g-editors' ) ) ) ), '', array( 'ROLE_MAP' => '{"g-editors":"editor"}' ) ); // phpcs:ignore
		$this->assertSame( $id, $r['user']->ID );
		$this->assertSame( array( 'administrator' ), get_userdata( $id )->roles );
	}

	public function test_allowed_domains_limit_who_signs_in(): void {
		$this->jane();
		$this->assertNotEmpty( $this->go( $this->signed(), '', array( 'ALLOWED_DOMAINS' => 'other.test, @Example.test' ) )['user'] );
		$this->assert_refused( fn() => $this->go( $this->signed(), '', array( 'ALLOWED_DOMAINS' => array( 'other.test' ) ) ), 'domain not listed, user exists' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'attrs' => array( Fixture::OID => array( 'oid-jane' ) ) ) ), '', array( 'ALLOWED_DOMAINS' => 'example.test' ) ), 'no email while a list is set' );
		$this->assert_refused( fn() => $this->create_with( array( 'ALLOWED_DOMAINS' => 'example.test' ), array( Config::CLAIM_EMAIL => array( 'evil@example.test.evil.com' ) ) ), 'suffix trick' );
	}

	public function test_attribute_names_are_configurable(): void {
		$u = $this->go(
			$this->signed(
				array(
					'name'  => 'uid-77',
					'attrs' => array(
						'mail'      => array( 'sam@example.test' ),
						'givenName' => array( 'Sam' ),
						'sn'        => array( 'Lee' ),
						'uid'       => array( 'u-77' ),
					),
				)
			),
			'',
			array(
				'AUTO_CREATE'     => true,
				'EMAIL_ATTR'      => 'mail',
				'FIRST_NAME_ATTR' => 'givenName',
				'LAST_NAME_ATTR'  => 'sn',
				'ID_ATTR'         => 'uid',
			)
		)['user'];
		$this->assertSame( 'sam@example.test', $u->user_email );
		$this->assertSame( 'Sam Lee', $u->display_name );
		$this->assertSame( 'u-77', get_user_meta( $u->ID, 'shakewell_saml_sso_id', true ) );
	}

	public function test_certificate_rollover_accepts_old_and_new_together(): void {
		$this->jane();
		$both = Fixture::acs( array( Fixture::pem_body( $this->old['cert'] ), Fixture::pem_body( $this->idp['cert'] ) ) );
		$this->assertNotEmpty( $both->consume( $this->signed(), '', '/' ) );
		$this->assertNotEmpty( $both->consume( $this->signed( array(), $this->old ), '', '/' ) );
		$this->assert_refused( fn() => $both->consume( $this->signed( array(), $this->other ), '', '/' ), 'a third certificate' );
		$this->assert_refused( fn() => $this->go( $this->signed( array(), $this->old ) ), 'removed certificate after rollover' );
	}

	public function test_relay_state_is_checked_again_on_the_way_back(): void {
		$this->jane();
		$this->assertSame( self::FALLBACK, $this->go( $this->signed(), 'https://evil.example/' )['redirect'] );
	}

	public function test_response_signed_mode(): void {
		$this->jane();
		$env = array( 'SIGNED_ELEMENT' => 'response' );
		$this->assertNotEmpty( $this->go( $this->signed( array( 'sign' => 'response' ) ), '', $env )['user'] );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'sign' => 'none' ) ), '', $env ), 'unsigned' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'sign' => 'assertion' ) ), '', $env ), 'only the assertion signed, envelope not' );
		$this->assert_refused( fn() => $this->go( $this->signed( array( 'sign' => 'response' ), $this->other ), '', $env ), 'wrong key' );
		$this->assert_refused(
			fn() => $this->go(
				$this->signed(
					array(
						'sign'   => 'response',
						'mutate' => function ( \DOMDocument $d ) {
							$d->getElementsByTagNameNS( 'urn:oasis:names:tc:SAML:2.0:assertion', 'NameID' )->item( 0 )->nodeValue = 'admin@example.test';
						},
					)
				),
				'',
				$env
			),
			'altered after signing'
		);
	}

	public function test_no_service_provider_certificate_is_needed_but_required_encryption_without_a_key_fails_closed(): void {
		$this->jane();
		$this->assertNotEmpty( $this->go( $this->signed() )['user'], 'plain, unencrypted response, no SP certificate configured' );
		// Requiring encryption without a key to decrypt with is a settings error: the library throws and nobody is signed in.
		$this->expectException( \OneLogin\Saml2\Error::class );
		$this->go( $this->signed(), '', array( 'WANT_ENCRYPTED' => 'true' ) );
	}
}
