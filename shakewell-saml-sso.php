<?php
/**
 * Plugin Name:       Shakewell Single Sign-On (SAML)
 * Plugin URI:        https://github.com/shakewellagency/shakewell-saml-sso
 * Description:       Sign in to wp-admin with Microsoft Entra ID or any SAML 2.0 identity provider. Off until configured.
 * Version:           0.1.1
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Shakewell
 * Author URI:        https://shakewell.agency
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       shakewell-saml-sso
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

defined( 'ABSPATH' ) || exit;

const VERSION = '0.1.1';
const FILE    = __FILE__;

// Composer-managed sites autoload the library from the root vendor folder; the release zip carries its own.
if ( ! class_exists( \OneLogin\Saml2\Auth::class ) && is_file( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
}

require_once __DIR__ . '/src/Refused.php';
require_once __DIR__ . '/src/Redirect.php';
require_once __DIR__ . '/src/Config.php';
require_once __DIR__ . '/src/Acs.php';
require_once __DIR__ . '/src/Plugin.php';

add_action( 'plugins_loaded', array( Plugin::class, 'boot' ) );
