<?php
/**
 * Removes everything the plugin stored when it is deleted from the Plugins screen.
 *
 * @package Shakewell\SamlSso
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Settings live in constants and the environment, never the database. Only per-user bookkeeping is stored; users themselves stay.
// Request and assertion ids are transients that expire within minutes.
foreach ( array( 'shakewell_saml_sso_id', 'shakewell_saml_sso_name_id', 'shakewell_saml_sso_session_index' ) as $shakewell_saml_sso_key ) {
	delete_metadata( 'user', 0, $shakewell_saml_sso_key, '', true );
}
