<?php
/**
 * Redirect targets.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso\Tests;

use Shakewell\SamlSso\Redirect;
use WP_UnitTestCase;

/**
 * Only this site is a valid place to land after sign-in.
 */
final class RedirectTest extends WP_UnitTestCase {

	private const FALLBACK = 'https://sso.example.test/wp/wp-admin/';

	/** @return array<string,array{string}> */
	public static function bad_targets(): array {
		$list = array(
			'//evil.example/x',
			'///evil.example',
			'/\\evil.example',
			'\\\\evil.example',
			'https://evil.example/',
			'http://sso.example.test/x',
			'https://sso.example.test.evil.example/',
			'https://evil.example/https://sso.example.test/',
			'https://sso.example.test@evil.example/',
			'https://user:pw@sso.example.test/',
			'https://sso.example.test:8443/',
			'javascript:alert(1)',
			'data:text/html,x',
			"/x\r\nSet-Cookie: a=b",
			'/ x',
			"https://sso.example.test/\t",
			'evil.example',
			'',
			str_repeat( '/a', 400 ),
		);
		return array_combine( array_map( fn( $s ) => substr( (string) wp_json_encode( $s ), 0, 50 ), $list ), array_map( fn( $s ) => array( $s ), $list ) );
	}

	/**
	 * @dataProvider bad_targets
	 * @param string $target Target.
	 */
	public function test_other_places_fall_back( string $target ): void {
		$this->assertSame( self::FALLBACK, Redirect::safe( $target, array( 'sso.example.test' ), 'https://sso.example.test', self::FALLBACK ) );
	}

	public function test_this_site_is_allowed(): void {
		$hosts = array( 'sso.example.test' );
		$this->assertSame( 'https://sso.example.test/wp/wp-admin/post.php?post=1', Redirect::safe( '/wp/wp-admin/post.php?post=1', $hosts, 'https://sso.example.test', self::FALLBACK ) );
		$this->assertSame( 'https://sso.example.test/venues/', Redirect::safe( 'https://sso.example.test/venues/', $hosts, 'https://sso.example.test', self::FALLBACK ) );
	}
}
