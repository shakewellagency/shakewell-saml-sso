<?php
/**
 * WordPress wiring.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress wiring for single sign-on. Endpoints:
 *   POST  <ACS url>                                        (default the site root) the response from the identity provider
 *   GET   wp-login.php?action=shakewell_saml_sso_login     start sign-in
 *   GET   wp-login.php?action=shakewell_saml_sso_metadata  service provider metadata, for the identity provider's admin
 *   GET   wp-login.php?action=shakewell_saml_sso_sls       sign-out answer or request from the identity provider
 * wp-login.php itself is untouched, so the local login form stays available as the way in when SSO is down.
 */
final class Plugin {

	public const ACTION_LOGIN    = 'shakewell_saml_sso_login';
	public const ACTION_METADATA = 'shakewell_saml_sso_metadata';
	public const ACTION_SLS      = 'shakewell_saml_sso_sls';

	/**
	 * Settings, set only while the plugin is switched on and complete.
	 *
	 * @var Config|null
	 */
	private static ?Config $config = null;

	/**
	 * Registers hooks, only when switched on and fully configured. Called on plugins_loaded.
	 */
	public static function boot(): void {
		self::$config = null;
		$config       = Config::from_environment( home_url( '/' ), site_url( 'wp-login.php' ) );
		if ( ! $config->enabled() ) {
			return; // Inert unless switched on.
		}
		if ( defined( 'MOSAML_PLUGIN_FILE' ) ) {
			self::log( 'enabled but the miniOrange SAML plugin is active; staying inert so only one handler answers.' );
			return;
		}
		if ( $config->missing() ) {
			self::log( 'enabled but missing settings: ' . implode( ', ', $config->missing() ) );
			return;
		}
		self::$config = $config;
		add_action( 'init', array( self::class, 'acs' ), 1 );
		add_action( 'login_form_' . self::ACTION_LOGIN, array( self::class, 'login' ) );
		add_action( 'login_form_' . self::ACTION_METADATA, array( self::class, 'metadata' ) );
		add_action( 'login_form_' . self::ACTION_SLS, array( self::class, 'sls' ) );
		add_action( 'login_form', array( self::class, 'link' ) );
		add_action( 'wp_logout', array( self::class, 'logout' ) );
	}

	/** The button on the login form. */
	public static function link(): void {
		/** Filters the text of the sign-in button, for example "Sign in with Microsoft". */
		$label = apply_filters( 'shakewell_saml_sso_button_label', __( 'Sign in with single sign-on', 'shakewell-saml-sso' ) );
		echo '<p><a class="button button-primary button-large" href="'
			. esc_url( add_query_arg( 'action', self::ACTION_LOGIN, site_url( 'wp-login.php' ) ) ) . '">' . esc_html( $label ) . '</a></p>';
	}

	/** Sends the browser to the identity provider. */
	public static function login(): void {
		$c = self::$config;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- starting sign-in changes nothing; the answer is bound to the request id made here.
		$requested = isset( $_GET['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) : '';
		$target    = Redirect::safe( $requested, $c->allowed_hosts(), $c->base_url(), admin_url() );
		try {
			$url = ( new Acs( $c ) )->login_url( $target );
		} catch ( \Throwable $e ) {
			self::fail( 'could not start sign-in: ' . get_class( $e ), 503 );
		}
		self::nocache();
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the identity provider's URL from configuration, not from the request.
		exit;
	}

	/** Answers a response posted to the ACS URL. */
	public static function acs(): void {
		$c = self::$config;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- a cross-site post from the identity provider cannot carry a nonce; the response is signature-checked and bound to our request id.
		if ( null === $c || 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! isset( $_POST['SAMLResponse'] ) ) {
			return;
		}
		// Only the configured ACS path answers; the path is compared, never the Host header.
		$path = rtrim( (string) wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ), PHP_URL_PATH ), '/' );
		if ( rtrim( (string) wp_parse_url( $c->acs_url(), PHP_URL_PATH ), '/' ) !== $path ) {
			return;
		}
		try {
			// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- base64 XML, validated and signature-checked by the library.
			$r = ( new Acs( $c ) )->consume( wp_unslash( (string) $_POST['SAMLResponse'] ), wp_unslash( (string) ( $_POST['RelayState'] ?? '' ) ), admin_url() );
			// phpcs:enable
		} catch ( Refused $e ) {
			self::fail( $e->getMessage(), 403 );
		} catch ( \Throwable $e ) {
			self::fail( get_class( $e ) . ': ' . $e->getMessage(), 400 ); // A forged or broken response is a 4xx, not a 500.
		}
		$user = $r['user'];
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, str_starts_with( $c->base_url(), 'https://' ) );
		update_user_meta( $user->ID, Acs::META_NAME, $r['nameId'] );
		update_user_meta( $user->ID, Acs::META_INDEX, (string) $r['sessionIndex'] );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own sign-in hook, so other plugins see this login.
		self::nocache();
		wp_redirect( $r['redirect'] ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- checked by Redirect::safe against the site's own hosts.
		exit;
	}

	/**
	 * Service provider metadata, validated.
	 *
	 * @param Config $config Settings.
	 * @return string
	 * @throws \RuntimeException When the settings produce invalid metadata.
	 */
	public static function metadata_xml( Config $config ): string {
		$settings = new Settings( $config->settings(), true );
		$xml      = $settings->getSPMetadata();
		if ( $settings->validateMetadata( $xml ) ) {
			throw new \RuntimeException( 'metadata invalid' );
		}
		return $xml;
	}

	/** Prints the service provider metadata. */
	public static function metadata(): void {
		try {
			$xml = self::metadata_xml( self::$config );
		} catch ( \Throwable $e ) {
			self::fail( 'metadata: ' . get_class( $e ), 500 );
		}
		self::nocache();
		header( 'Content-Type: application/samlmetadata+xml; charset=UTF-8' );
		echo $xml; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- XML built and validated by the library.
		exit;
	}

	/**
	 * Sign out at the identity provider too, when the user came in through it and a sign-out URL is configured.
	 *
	 * @param int $user_id The user who signed out.
	 */
	public static function logout( int $user_id ): void {
		if ( null === self::$config || ! get_user_meta( $user_id, Acs::META_NAME, true ) || ! isset( self::$config->settings()['idp']['singleLogoutService'] ) ) {
			return;
		}
		$name_id = (string) get_user_meta( $user_id, Acs::META_NAME, true );
		$index   = (string) get_user_meta( $user_id, Acs::META_INDEX, true );
		delete_user_meta( $user_id, Acs::META_NAME );
		delete_user_meta( $user_id, Acs::META_INDEX );
		try {
			new Acs( self::$config );
			$url = ( new Auth( self::$config->settings() ) )->logout( home_url( '/' ), array(), $name_id, '' !== $index ? $index : null, true );
		} catch ( \Throwable $e ) {
			self::log( 'sign-out at the identity provider failed: ' . get_class( $e ) );
			return; // Local sign-out has already happened.
		}
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the identity provider's URL from configuration.
		exit;
	}

	/**
	 * Handles the identity provider's sign-out answer or request.
	 *
	 * @throws \RuntimeException Never past this method: it is caught and shown as a 400.
	 */
	public static function sls(): void {
		$c = self::$config;
		// ponytail: a sign-out request from the identity provider must be signed or it is ignored (stops a forged one logging someone out). If the provider does not sign them, sign-out from its side is not supported.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the identity provider's request, signature-checked by the library.
		if ( isset( $_GET['SAMLRequest'] ) && ! isset( $_GET['Signature'] ) ) {
			self::fail( 'unsigned sign-out request', 403 );
		}
		try {
			new Acs( $c ); // Pins host, scheme and port to the configured base URL, not the request.
			$auth = new Auth( $c->settings() );
			$url  = $auth->processSLO(
				false,
				null,
				true,
				function () {
					wp_destroy_current_session();
					wp_clear_auth_cookie();
				},
				true
			);
			if ( $auth->getErrors() ) {
				throw new \RuntimeException( implode( ',', $auth->getErrors() ) . ' ' . $auth->getLastErrorReason() );
			}
		} catch ( \Throwable $e ) {
			self::fail( 'sign-out: ' . $e->getMessage(), 400 );
		}
		wp_safe_redirect( '' !== (string) $url ? $url : home_url( '/' ) );
		exit;
	}

	/** Asks browsers and caches not to keep the response. */
	private static function nocache(): void {
		if ( ! headers_sent() ) {
			nocache_headers();
		}
	}

	/**
	 * Writes a line to the PHP error log. Never pass personal data here.
	 *
	 * @param string $reason What happened.
	 */
	private static function log( string $reason ): void {
		error_log( '[shakewell-saml-sso] ' . $reason ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- the one place the plugin logs; sign-in problems belong in the server log.
	}

	/**
	 * A plain 4xx page for the visitor; the reason goes to the log only.
	 *
	 * @param string $reason Why, for the log.
	 * @param int    $status HTTP status.
	 */
	private static function fail( string $reason, int $status ): void {
		self::log( $reason );
		self::nocache();
		wp_die(
			esc_html__( 'We could not sign you in. Please try again, or contact the site administrator if it keeps happening.', 'shakewell-saml-sso' ),
			esc_html__( 'Sign-in problem', 'shakewell-saml-sso' ),
			array(
				'response'  => (int) $status,
				'link_url'  => esc_url( site_url( 'wp-login.php' ) ),
				'link_text' => esc_html__( 'Back to the login page', 'shakewell-saml-sso' ),
			)
		);
	}
}
