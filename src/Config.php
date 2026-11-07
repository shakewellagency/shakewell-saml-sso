<?php
/**
 * Settings.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

defined( 'ABSPATH' ) || exit;

/**
 * Single sign-on settings, read from PHP constants (wp-config.php) or environment variables.
 * Nothing is read from or stored in the database.
 *
 * Every setting is looked up as the constant, then the environment variable, named SHAKEWELL_SAML_SSO_<KEY>.
 */
final class Config {

	public const CLAIM_EMAIL  = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
	public const CLAIM_FIRST  = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname';
	public const CLAIM_LAST   = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname';
	public const CLAIM_OID    = 'http://schemas.microsoft.com/identity/claims/objectidentifier';
	public const CLAIM_GROUPS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';

	/** Seconds of clock difference tolerated on top of the assertion's own window (the library allows 180). */
	public const CLOCK_SKEW = 60;

	public const PREFIX = 'SHAKEWELL_SAML_SSO_';

	/** Setting keys, each read as SHAKEWELL_SAML_SSO_<KEY>. */
	private const KEYS = array(
		'ENABLED',
		'IDP_ENTITY_ID',
		'IDP_SSO_URL',
		'IDP_SLO_URL',
		'IDP_CERTS',
		'SIGNED_ELEMENT',
		'SP_BASE_URL',
		'SP_ENTITY_ID',
		'ACS_URL',
		'SP_CERT',
		'SP_KEY',
		'WANT_ENCRYPTED',
		'EMAIL_ATTR',
		'FIRST_NAME_ATTR',
		'LAST_NAME_ATTR',
		'ID_ATTR',
		'GROUP_CLAIM',
		'ROLE_MAP',
		'DEFAULT_ROLE',
		'AUTO_CREATE',
		'ALLOWED_DOMAINS',
	);

	/**
	 * Settings by key (see KEYS). Values are strings, booleans or arrays, as the constant or variable gave them.
	 *
	 * @param array<string,mixed> $env       Settings.
	 * @param string              $home_url  The site's home URL.
	 * @param string              $login_url The site's wp-login.php URL.
	 */
	public function __construct( private array $env, private string $home_url, private string $login_url ) {
	}

	/**
	 * Reads every setting from constants, then environment variables.
	 *
	 * @param string $home_url  The site's home URL.
	 * @param string $login_url The site's wp-login.php URL.
	 */
	public static function from_environment( string $home_url, string $login_url ): self {
		$env = array();
		foreach ( self::KEYS as $key ) {
			$name = self::PREFIX . $key;
			if ( defined( $name ) ) {
				$value = constant( $name );
				$found = true;
			} else {
				$value = getenv( $name );
				$found = false !== $value;
			}
			if ( $found && null !== $value && '' !== $value && array() !== $value ) {
				$env[ $key ] = $value;
			}
		}
		return new self( $env, $home_url, $login_url );
	}

	/**
	 * A text setting, or the default when unset.
	 *
	 * @param string $key     Setting key.
	 * @param string $fallback Default.
	 */
	private function text( string $key, string $fallback = '' ): string {
		$v = $this->env[ $key ] ?? '';
		return is_string( $v ) && '' !== trim( $v ) ? trim( $v ) : $fallback;
	}

	/**
	 * A yes/no setting.
	 *
	 * @param string $key     Setting key.
	 * @param bool   $fallback Used when unset.
	 */
	private function flag( string $key, bool $fallback ): bool {
		return isset( $this->env[ $key ] ) ? filter_var( $this->env[ $key ], FILTER_VALIDATE_BOOLEAN ) : $fallback;
	}

	/** Off unless switched on. */
	public function enabled(): bool {
		return $this->flag( 'ENABLED', false );
	}

	/**
	 * Names of required settings that are missing.
	 *
	 * @return string[]
	 */
	public function missing(): array {
		$m = array();
		foreach ( array( 'IDP_ENTITY_ID', 'IDP_SSO_URL' ) as $key ) {
			if ( '' === $this->text( $key ) ) {
				$m[] = self::PREFIX . $key;
			}
		}
		if ( ! $this->idp_certs() ) {
			$m[] = self::PREFIX . 'IDP_CERTS';
		}
		return $m;
	}

	/**
	 * Certificate bodies (base64, no header). PEM blocks, comma-separated base64, or an array of either.
	 *
	 * @return string[]
	 */
	public function idp_certs(): array {
		$out = array();
		foreach ( (array) ( $this->env['IDP_CERTS'] ?? '' ) as $chunk ) {
			if ( ! is_string( $chunk ) ) {
				continue;
			}
			$parts = preg_match_all( '/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $chunk, $m ) ? $m[1] : explode( ',', $chunk );
			foreach ( $parts as $p ) {
				$p = preg_replace( '/\s+/', '', $p );
				if ( '' !== $p && preg_match( '#^[A-Za-z0-9+/=]+$#', $p ) ) {
					$out[] = $p;
				}
			}
		}
		return array_values( array_unique( $out ) );
	}

	/** The host the identity provider is registered against. Default: the site's home URL. */
	public function base_url(): string {
		return rtrim( $this->text( 'SP_BASE_URL', $this->home_url ), '/' );
	}

	/** Our identifier at the identity provider. */
	public function entity_id(): string {
		return $this->text( 'SP_ENTITY_ID', $this->base_url() );
	}

	/** Where the identity provider posts the response. Default: the site root. */
	public function acs_url(): string {
		return $this->text( 'ACS_URL', $this->base_url() . '/' );
	}

	/** Where the identity provider answers a sign-out. */
	public function slo_url(): string {
		return $this->login_url . ( str_contains( $this->login_url, '?' ) ? '&' : '?' ) . 'action=' . Plugin::ACTION_SLS;
	}

	/**
	 * Hosts a redirect target may name: the site's own, nothing else.
	 *
	 * @return string[]
	 */
	public function allowed_hosts(): array {
		return array_values(
			array_unique(
				array_filter(
					array(
						wp_parse_url( $this->base_url(), PHP_URL_HOST ),
						wp_parse_url( $this->home_url, PHP_URL_HOST ),
						wp_parse_url( $this->login_url, PHP_URL_HOST ),
					)
				)
			)
		);
	}

	/** Which element the identity provider signs: "assertion" (default) or "response". */
	public function signed_element(): string {
		return 'response' === $this->text( 'SIGNED_ELEMENT' ) ? 'response' : 'assertion';
	}

	/** Attribute holding the email address. */
	public function email_attr(): string {
		return $this->text( 'EMAIL_ATTR', self::CLAIM_EMAIL );
	}

	/** Attribute holding the first name. */
	public function first_name_attr(): string {
		return $this->text( 'FIRST_NAME_ATTR', self::CLAIM_FIRST );
	}

	/** Attribute holding the last name. */
	public function last_name_attr(): string {
		return $this->text( 'LAST_NAME_ATTR', self::CLAIM_LAST );
	}

	/** Attribute holding a stable user id (Entra: object id). Empty value in the response is fine. */
	public function id_attr(): string {
		return $this->text( 'ID_ATTR', self::CLAIM_OID );
	}

	/** Attribute holding group ids. */
	public function group_claim(): string {
		return $this->text( 'GROUP_CLAIM', self::CLAIM_GROUPS );
	}

	/**
	 * Group id => role, used only when a new user is created. JSON or an array.
	 *
	 * @return array<string,string>
	 */
	public function role_map(): array {
		$map = $this->env['ROLE_MAP'] ?? array();
		if ( is_string( $map ) ) {
			$map = json_decode( $map, true );
		}
		return is_array( $map ) ? array_filter( $map, 'is_string' ) : array();
	}

	/** Role for a new user with no mapped group. */
	public function default_role(): string {
		return $this->text( 'DEFAULT_ROLE', 'subscriber' );
	}

	/** Whether an unknown user is created. Default: no. */
	public function auto_create(): bool {
		return $this->flag( 'AUTO_CREATE', false );
	}

	/**
	 * Email domains allowed to sign in (lower case, no "@"). Empty means any.
	 *
	 * @return string[]
	 */
	public function allowed_domains(): array {
		$raw = $this->env['ALLOWED_DOMAINS'] ?? array();
		if ( is_string( $raw ) ) {
			$raw = explode( ',', $raw );
		}
		$out = array();
		foreach ( (array) $raw as $d ) {
			$d = strtolower( ltrim( trim( (string) $d ), '@' ) );
			if ( '' !== $d ) {
				$out[] = $d;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * The settings array for onelogin/php-saml. Strict mode, a signature required, no SP certificate needed.
	 *
	 * @return array<string,mixed>
	 */
	public function settings(): array {
		$redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
		$idp      = array(
			'entityId'            => $this->text( 'IDP_ENTITY_ID' ),
			'singleSignOnService' => array(
				'url'     => $this->text( 'IDP_SSO_URL' ),
				'binding' => $redirect,
			),
			'x509certMulti'       => array( 'signing' => $this->idp_certs() ),
		);
		if ( '' !== $this->text( 'IDP_SLO_URL' ) ) {
			$idp['singleLogoutService'] = array(
				'url'     => $this->text( 'IDP_SLO_URL' ),
				'binding' => $redirect,
			);
		}
		$response_signed = 'response' === $this->signed_element();
		return array(
			'strict'   => true,
			'debug'    => false,
			'baseurl'  => $this->base_url(),
			'sp'       => array(
				'entityId'                 => $this->entity_id(),
				'assertionConsumerService' => array(
					'url'     => $this->acs_url(),
					'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
				),
				'singleLogoutService'      => array(
					'url'     => $this->slo_url(),
					'binding' => $redirect,
				),
				'NameIDFormat'             => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
				'x509cert'                 => $this->text( 'SP_CERT' ),
				'privateKey'               => $this->text( 'SP_KEY' ),
			),
			'idp'      => $idp,
			'security' => array(
				// Exactly one of the two is required to be signed, by a listed certificate.
				'wantAssertionsSigned'       => ! $response_signed,
				'wantMessagesSigned'         => $response_signed,
				'wantAssertionsEncrypted'    => $this->flag( 'WANT_ENCRYPTED', false ),
				'wantNameId'                 => true,
				'wantXMLValidation'          => true,
				'destinationStrictlyMatches' => true,
				'rejectUnsolicitedResponsesWithInResponseTo' => true,
				'allowRepeatAttributeName'   => false,
				'rejectDeprecatedAlgorithm'  => true,
				'signatureAlgorithm'         => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
				'digestAlgorithm'            => 'http://www.w3.org/2001/04/xmlenc#sha256',
				'requestedAuthnContext'      => false,
			),
		);
	}
}
