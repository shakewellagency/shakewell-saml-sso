<?php
/**
 * A sign-in that must be refused.
 *
 * @package Shakewell\SamlSso
 */

namespace Shakewell\SamlSso;

defined( 'ABSPATH' ) || exit;

/**
 * The reason goes to the log only, and never includes personal data. The visitor sees a fixed message.
 */
final class Refused extends \RuntimeException {
}
