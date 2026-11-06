<?php
/**
 * Assertion consumer.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

defined( 'ABSPATH' ) || exit;

/**
 * Turns a SAML response from the identity provider into a WordPress user, or refuses it.
 * The signature, audience, destination, timing and InResponseTo checks are the library's (strict mode);
 * this class adds the request binding, replay store, tighter clock, user matching and roles.
 */
final class Acs {

	private const REQ          = 'shakewell_saml_sso_req_';
	private const SEEN         = 'shakewell_saml_sso_seen_';
	private const MAX_RESPONSE = 524288;

	public const META_ID    = 'shakewell_saml_sso_id';
	public const META_NAME  = 'shakewell_saml_sso_name_id';
	public const META_INDEX = 'shakewell_saml_sso_session_index';

	/**
	 * Pins the host, scheme and port the library checks against.
	 *
	 * @param Config $config Settings.
	 */
	public function __construct( private Config $config ) {
		// Never derive the host, scheme or port from the request: it is client-controlled.
		$u = wp_parse_url( $config->base_url() );
		Utils::setSelfProtocol( $u['scheme'] ?? 'https' );
		Utils::setSelfHost( $u['host'] ?? '' );
		Utils::setSelfPort( $u['port'] ?? ( 'https' === ( $u['scheme'] ?? 'https' ) ? 443 : 80 ) );
	}

	/**
	 * Transient key for a request id. Hashed: the id comes back from the browser.
	 *
	 * @param string $id Request id.
	 */
	private static function req_key( string $id ): string {
		return self::REQ . hash( 'sha256', $id );
	}

	/**
	 * URL that sends the browser to the identity provider. Remembers the request id so only our own requests are answered.
	 *
	 * @param string $relay_state Where to go after sign-in.
	 */
	public function login_url( string $relay_state ): string {
		$auth = new Auth( $this->config->settings() );
		$url  = $auth->login( $relay_state, array(), false, false, true );
		set_transient( self::req_key( $auth->getLastRequestID() ), 1, 600 );
		return $url;
	}

	/**
	 * Validates a response and returns the user to sign in.
	 *
	 * @param string $saml_response     Base64 response as posted.
	 * @param string $relay_state       Relay state as posted.
	 * @param string $fallback_redirect Used when the relay state is not acceptable.
	 * @return array{user: \WP_User, redirect: string, nameId: string, sessionIndex: ?string}
	 * @throws Refused When the response must not sign anyone in.
	 */
	public function consume( string $saml_response, string $relay_state, string $fallback_redirect ): array {
		if ( '' === $saml_response || strlen( $saml_response ) > self::MAX_RESPONSE ) {
			throw new Refused( 'malformed response' );
		}
		$request_id = $this->in_response_to( $saml_response );
		if ( '' === $request_id || ! get_transient( self::req_key( $request_id ) ) ) {
			throw new Refused( 'response to a request we did not make' );
		}
		delete_transient( self::req_key( $request_id ) ); // One answer per request.

		$_POST['SAMLResponse'] = $saml_response; // The library reads it from here; it is validated and signature-checked below.
		$auth                  = new Auth( $this->config->settings() );
		$auth->processResponse( $request_id );
		if ( $auth->getErrors() || ! $auth->isAuthenticated() ) {
			throw new Refused( 'response rejected: ' . implode( ',', $auth->getErrors() ) . ' ' . $auth->getLastErrorReason() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- the reason goes to the log, never to a page.
		}
		$this->check_window( $auth );
		$this->remember_assertion( $auth );

		$name_id = (string) $auth->getNameId();
		$user    = $this->resolve_user( $name_id, $auth->getAttributes() );
		return array(
			'user'         => $user,
			'redirect'     => Redirect::safe( $relay_state, $this->config->allowed_hosts(), $this->config->base_url(), $fallback_redirect ),
			'nameId'       => $name_id,
			'sessionIndex' => $auth->getSessionIndex(),
		);
	}

	/**
	 * The InResponseTo of the response element, read from XML that refuses DOCTYPE.
	 *
	 * @param string $b64 Base64 response.
	 */
	private function in_response_to( string $b64 ): string {
		$xml = base64_decode( $b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding a SAML message, not obfuscated code.
		if ( false === $xml ) {
			return '';
		}
		try {
			$doc = Utils::loadXML( new \DOMDocument(), $xml );
		} catch ( \Throwable $e ) {
			return '';
		}
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM API.
		return $doc instanceof \DOMDocument ? (string) $doc->documentElement?->getAttribute( 'InResponseTo' ) : '';
	}

	/**
	 * The library allows 180 s of clock drift; this keeps it to CLOCK_SKEW.
	 *
	 * @param Auth $auth Validated response.
	 * @throws Refused When the assertion is outside its window.
	 */
	private function check_window( Auth $auth ): void {
		$now = time();
		$noa = $auth->getLastAssertionNotOnOrAfter();
		if ( null === $noa || $noa + Config::CLOCK_SKEW <= $now ) {
			throw new Refused( 'assertion expired' );
		}
		$dom = new \DOMDocument();
		$dom->loadXML( (string) $auth->getLastResponseXML(), LIBXML_NONET );
		$xp = new \DOMXPath( $dom );
		$xp->registerNamespace( 's', 'urn:oasis:names:tc:SAML:2.0:assertion' );
		foreach ( $xp->query( '//s:Assertion/s:Conditions/@NotBefore' ) as $nb ) {
			if ( strtotime( $nb->value ) > $now + Config::CLOCK_SKEW ) {
				throw new Refused( 'assertion not yet valid' );
			}
		}
	}

	/**
	 * Each assertion id works once, until it would have expired anyway.
	 *
	 * @param Auth $auth Validated response.
	 * @throws Refused When the assertion was used before.
	 */
	private function remember_assertion( Auth $auth ): void {
		$key = self::SEEN . hash( 'sha256', (string) $auth->getLastAssertionId() );
		if ( get_transient( $key ) ) {
			throw new Refused( 'assertion replayed' );
		}
		// ponytail: check-then-set, not atomic; two simultaneous posts of one assertion still log in the same user. Use add_option if that ever matters.
		set_transient( $key, 1, max( 60, (int) $auth->getLastAssertionNotOnOrAfter() - time() + Config::CLOCK_SKEW ) );
	}

	/**
	 * Finds the user by the stored provider id, then login (the sanitised NameID), then email. Creates one only when allowed.
	 *
	 * @param string                 $name_id NameID.
	 * @param array<string,string[]> $attrs   Attributes.
	 * @throws Refused When nobody may be signed in.
	 */
	private function resolve_user( string $name_id, array $attrs ): \WP_User {
		$first = fn( string $claim ): string => (string) ( $attrs[ $claim ][0] ?? '' );
		$email = strtolower( $first( $this->config->email_attr() ) );
		$oid   = '' === $this->config->id_attr() ? '' : $first( $this->config->id_attr() );
		$login = sanitize_user( $name_id, true );
		if ( '' === $login && '' === $email ) {
			throw new Refused( 'no identity in assertion' );
		}
		$domains = $this->config->allowed_domains();
		if ( $domains && ! in_array( substr( strrchr( '@' . $email, '@' ), 1 ), $domains, true ) ) {
			throw new Refused( 'email domain not allowed' );
		}

		$user = null;
		if ( '' !== $oid ) {
			// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- a rare lookup by the provider's own id, at sign-in only.
			$by_id = get_users(
				array(
					'meta_key'   => self::META_ID, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
					'meta_value' => $oid, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
					'number'     => 2,
				)
			);
			if ( count( $by_id ) > 1 ) {
				throw new Refused( 'provider id matches several users' );
			}
			$user = $by_id[0] ?? null;
		}
		if ( ! $user && '' !== $login ) {
			$user = get_user_by( 'login', $login );
		}
		if ( ! $user && '' !== $email ) {
			$user = get_user_by( 'email', $email );
		}

		if ( ! $user ) {
			return $this->create_user( $login, $email, $first( $this->config->first_name_attr() ), $first( $this->config->last_name_attr() ), $oid, array_map( 'strval', $attrs[ $this->config->group_claim() ] ?? array() ) );
		}
		$stored = (string) get_user_meta( $user->ID, self::META_ID, true );
		if ( '' !== $stored && '' !== $oid && ! hash_equals( $stored, $oid ) ) {
			throw new Refused( 'provider id does not match the account' );
		}
		if ( '' === $stored && '' !== $oid ) {
			update_user_meta( $user->ID, self::META_ID, $oid );
		}
		return $user; // Roles of an existing user are never changed.
	}

	/**
	 * Creates a user, if creation is on.
	 *
	 * @param string   $login  Login.
	 * @param string   $email  Email.
	 * @param string   $first  First name.
	 * @param string   $last   Last name.
	 * @param string   $oid    Provider id.
	 * @param string[] $groups Group ids.
	 * @throws Refused When creation is off or the data is not enough.
	 */
	private function create_user( string $login, string $email, string $first, string $last, string $oid, array $groups ): \WP_User {
		if ( ! $this->config->auto_create() ) {
			throw new Refused( 'unknown user and creation is off' );
		}
		if ( '' === $login || ! is_email( $email ) ) {
			throw new Refused( 'cannot create a user without a login and a valid email' );
		}
		$role = $this->config->default_role();
		foreach ( $this->config->role_map() as $group => $mapped ) {
			if ( in_array( (string) $group, $groups, true ) ) {
				$role = $mapped;
				break;
			}
		}
		if ( 'administrator' === $role ) {
			throw new Refused( 'refusing to create an administrator from a sign-in' );
		}
		if ( ! wp_roles()->is_role( $role ) ) {
			throw new Refused( 'the role for a new user does not exist' );
		}
		$id = wp_insert_user(
			array(
				'user_login'   => $login,
				'user_email'   => $email,
				'user_pass'    => wp_generate_password( 40 ),
				'first_name'   => $first,
				'last_name'    => $last,
				'display_name' => '' !== trim( "$first $last" ) ? trim( "$first $last" ) : $login,
				'role'         => $role,
			)
		);
		if ( is_wp_error( $id ) ) {
			throw new Refused( 'user creation failed: ' . $id->get_error_code() ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- log only.
		}
		if ( '' !== $oid ) {
			update_user_meta( $id, self::META_ID, $oid );
		}
		return get_user_by( 'id', $id );
	}
}
