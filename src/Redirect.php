<?php
/**
 * Redirect target checks.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

defined( 'ABSPATH' ) || exit;

/**
 * Where to send someone after sign-in: this site only, never a host taken from the request.
 */
final class Redirect {

	/**
	 * Returns the target if it is on this site, otherwise the fallback.
	 *
	 * @param string|null $target        Requested target.
	 * @param string[]    $allowed_hosts The site's own hosts.
	 * @param string      $base_url      Absolute URL that relative targets are resolved against (never the Host header).
	 * @param string      $fallback      Used when the target is not acceptable.
	 */
	public static function safe( ?string $target, array $allowed_hosts, string $base_url, string $fallback ): string {
		$t = (string) $target;
		// Control characters, spaces and backslashes are how browsers get tricked into treating a path as a host.
		if ( '' === $t || strlen( $t ) > 512 || preg_match( '/[\x00-\x20\x7f\\\\]/', $t ) ) {
			return $fallback;
		}
		if ( '/' === $t[0] ) {
			return '/' === ( $t[1] ?? '' ) ? $fallback : rtrim( $base_url, '/' ) . $t;
		}
		$p = wp_parse_url( $t );
		if ( ! $p || ! isset( $p['scheme'], $p['host'] ) || isset( $p['user'] ) || isset( $p['pass'] ) ) {
			return $fallback;
		}
		$base        = wp_parse_url( $base_url );
		$same_scheme = strtolower( $p['scheme'] ) === strtolower( $base['scheme'] ?? 'https' );
		$host_ok     = in_array( strtolower( $p['host'] ), array_map( 'strtolower', $allowed_hosts ), true );
		$port_ok     = ( $p['port'] ?? null ) === ( $base['port'] ?? null );
		return $same_scheme && $host_ok && $port_ok ? $t : $fallback;
	}
}
