=== Shakewell Single Sign-On (SAML) ===
Contributors: shakewellagency
Tags: saml, sso, single sign-on, login, microsoft entra
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let editors sign in to wp-admin with Microsoft Entra ID or any SAML 2.0 identity provider. Configured in code, off until you switch it on.

== Description ==

Editors sign in with the company account instead of a WordPress password. The plugin is a small, strict SAML 2.0 service provider built on the maintained [onelogin/php-saml](https://github.com/SAML-Toolkits/php-saml) library. Signature and certificate checks are done by that library, never by code in this plugin.

What it does:

* Adds a "Sign in with single sign-on" button to the login form and answers the identity provider's response.
* Accepts a response only if it is signed by one of your listed certificates, is an answer to a sign-in this site started, is addressed to this site (audience, destination, recipient), comes from your identity provider (issuer), and is inside its validity window (60 seconds of clock tolerance). Each assertion works once.
* Matches the person to an existing user by a stored provider id, then by login (the NameID), then by email. Existing users keep their roles.
* Creates unknown users only if you turn that on, with a default role or a role chosen from their groups. It never creates an administrator.
* Can limit sign-in to a list of email domains.
* Publishes service provider metadata for the identity provider's admin.
* Sends visitors to this site's own pages only after sign-in.

What it deliberately does not do:

* No settings screen, no options, no database tables. Every setting is a constant or environment variable, so nothing secret or security-relevant is editable from wp-admin.
* It does not replace or redirect wp-login.php. The normal login form keeps working, which is your emergency way in.
* It does not need a certificate or private key of its own. Signed requests and encrypted assertions are optional.
* No tracking and no calls home.

Off by default. Nothing happens until `SHAKEWELL_SAML_SSO_ENABLED` is true and the required settings are present.

= External services =

This plugin talks to one outside service: the SAML 2.0 identity provider you configure (for example Microsoft Entra ID, `login.microsoftonline.com`). It is required for the plugin to do anything.

* What is sent: the browser is redirected to the identity provider's sign-in URL with a SAML authentication request (a request id, this site's identifier and sign-in return address). If you configure a sign-out URL, a sign-out request carrying the user's identifier at the provider is sent when they log out.
* What is received: the signed response the identity provider posts back through the user's browser, containing the user's identifier, email address, name and, if configured, group ids. Only the user's own browser is involved; the server of this site does not call the identity provider.
* When: only when someone chooses the sign-in button, or logs out of a session that began with single sign-on.
* Terms and privacy policy: those of the identity provider you choose. For Microsoft Entra ID: [Microsoft Services Agreement](https://www.microsoft.com/servicesagreement) and [Privacy Statement](https://privacy.microsoft.com/privacystatement).

= Bundled libraries =

The release zip includes two libraries in its `vendor` folder, both under licences compatible with the GPL: [onelogin/php-saml](https://github.com/SAML-Toolkits/php-saml) 4.3.2 (MIT) and [robrichards/xmlseclibs](https://github.com/robrichards/xmlseclibs) 3.1.5 (BSD 3-Clause). Their source is plain PHP, unmodified. They need the PHP extensions openssl, dom and xml, which most hosts enable.

== Installation ==

1. Install the plugin (upload the release zip, which includes the library, or require it with Composer) and activate it.
2. Add the settings below to `wp-config.php` (or set them as environment variables).
3. Register the site with your identity provider, using the metadata URL below.
4. Check that the local login still works, then set `SHAKEWELL_SAML_SSO_ENABLED` to true.

= Settings =

Each setting is a PHP constant (or an environment variable) named `SHAKEWELL_SAML_SSO_<NAME>`. A constant wins over an environment variable.

* `ENABLED`: `true` to switch on. Default off..
* `IDP_ENTITY_ID` (required): the identity provider's entity id. Entra: "Microsoft Entra Identifier"..
* `IDP_SSO_URL` (required): the identity provider's sign-in URL. Entra: "Login URL"..
* `IDP_CERTS` (required): the identity provider's signing certificate. PEM text, or base64 only, several separated by commas, or a PHP array. List the old and new certificate together during a rollover..
* `IDP_SLO_URL`: the identity provider's sign-out URL. Without it, logging out only ends the WordPress session..
* `SIGNED_ELEMENT`: `assertion` (default) if the identity provider signs the assertion, or `response` if it signs only the response envelope. One of the two must be signed. Entra's default signs the assertion; choose "Sign SAML response and assertion" or set `response` to match what you configured.
* `SP_BASE_URL`: the address the identity provider is registered against. Default: the site's home URL..
* `SP_ENTITY_ID`: this site's identifier at the identity provider. Default: the base URL..
* `ACS_URL`: where the identity provider posts the response. Default: the site root (`https://example.com/`)..
* `EMAIL_ATTR`, `FIRST_NAME_ATTR`, `LAST_NAME_ATTR`: attribute names. Defaults are the Microsoft claim URIs for email address, given name and surname.
* `ID_ATTR`: attribute holding a stable user id, stored on first sign-in and then required to match. Default is Entra's object id claim.
* `GROUP_CLAIM`: attribute holding group ids. Default is Entra's groups claim..
* `AUTO_CREATE`: `true` to create users who do not exist yet. Default `false`..
* `DEFAULT_ROLE`: role for a new user with no mapped group. Default `subscriber`..
* `ROLE_MAP`: group id to role, as JSON (`{"group-id":"editor"}`) or a PHP array. Used only when a user is created. The first match wins..
* `ALLOWED_DOMAINS`: comma-separated list or array of email domains allowed to sign in, for example `example.com,example.org`. Empty means any. When set, a response without an email address is refused.
* `SP_CERT`, `SP_KEY`, `WANT_ENCRYPTED`: only if you want the plugin to decrypt assertions. Not needed for signed, unencrypted responses..

Example for `wp-config.php`:

`define( 'SHAKEWELL_SAML_SSO_ENABLED', true );`
`define( 'SHAKEWELL_SAML_SSO_IDP_ENTITY_ID', 'https://sts.windows.net/TENANT-ID/' );`
`define( 'SHAKEWELL_SAML_SSO_IDP_SSO_URL', 'https://login.microsoftonline.com/TENANT-ID/saml2' );`
`define( 'SHAKEWELL_SAML_SSO_IDP_CERTS', 'MIIC...base64 of the certificate...' );`
`define( 'SHAKEWELL_SAML_SSO_AUTO_CREATE', true );`
`define( 'SHAKEWELL_SAML_SSO_DEFAULT_ROLE', 'editor' );`

= Microsoft Entra ID setup =

1. In Entra admin center, Enterprise applications, New application, Create your own application, "Integrate any other application you don't find in the gallery". Set Single sign-on to SAML.
2. Basic SAML Configuration: Identifier (Entity ID) is the value of `SP_ENTITY_ID` (by default your site address, for example `https://example.com`). Reply URL (Assertion Consumer Service URL) is the value of `ACS_URL` (by default `https://example.com/`). You can also upload the metadata file from this site: `https://example.com/wp-login.php?action=shakewell_saml_sso_metadata` (use your own login address; if WordPress lives in a subfolder, include it).
3. Attributes and Claims: keep the default claims (email address, given name, surname, user principal name). Add the object identifier claim if it is missing. To use groups, add a groups claim sent as group ids.
4. SAML Certificates: keep "Sign SAML assertion" (or choose "Sign SAML response and assertion"). Leave encryption off. Download "Certificate (Base64)" and put its text in `IDP_CERTS`.
5. Copy "Login URL", "Microsoft Entra Identifier" and optionally "Logout URL" from the "Set up" section into `IDP_SSO_URL`, `IDP_ENTITY_ID` and `IDP_SLO_URL`.
6. Properties: turn on "Assignment required" and assign the people or groups who may sign in.
7. Set `ENABLED` and try signing in from a private window.

= Certificate rollover =

The signing certificate expires. Before it does:

1. In Entra, create a new SAML signing certificate (do not make it active yet) and download its base64 text.
2. Add it to `IDP_CERTS` next to the current one (comma-separated, or two PEM blocks) and deploy. Both are now trusted.
3. In Entra, make the new certificate active.
4. Check that sign-in works, then remove the old certificate from `IDP_CERTS` and deploy.

= Emergency access (break-glass) =

The plugin never replaces or redirects wp-login.php, so the normal username and password form keeps working if the identity provider is down or misconfigured. Keep at least one administrator with a working local password. To switch the plugin off at once, set `SHAKEWELL_SAML_SSO_ENABLED` to false (or remove it). If you are locked out of every account, use WP-CLI on the server, for example `wp user update ADMIN --user_pass=NEW`.

== Frequently Asked Questions ==

= Where do I find the metadata for my identity provider? =

At `wp-login.php?action=shakewell_saml_sso_metadata` on your site. It lists the entity id, the return address and the sign-out address.

= Do I need a certificate or private key? =

No. Only the identity provider's certificate is needed, and it comes from your configuration. A key of your own is needed only to decrypt assertions.

= Why was my sign-in refused? =

Visitors see a plain message. The reason is written to the PHP error log with the prefix `[shakewell-saml-sso]`. The log never contains names, email addresses or user ids.

= Can anyone with a company account sign in? =

Only if the identity provider lets them (use "Assignment required" in Entra), and, if you set `ALLOWED_DOMAINS`, only for those email domains. Unknown users are refused unless `AUTO_CREATE` is true. A new user is never made an administrator.

= My identity provider signs only the response, not the assertion. =

Set `SIGNED_ELEMENT` to `response`.

= Does it work with the miniOrange SAML plugin installed? =

The plugin stays inert while the miniOrange plugin is active, so only one handler answers. Set it up, deactivate miniOrange, then enable this plugin.

= Which users get which role? =

Existing users keep their roles. A new user gets the role of the first `ROLE_MAP` group they belong to, otherwise `DEFAULT_ROLE`.

= How do I change the sign-in button text? =

Use the `shakewell_saml_sso_button_label` filter.

= Where do I report a security problem? =

Please do not open a public issue. Follow SECURITY.md in the plugin's repository.

== Changelog ==

= 0.1.1 =
* Breaking: the older `SAML_*` setting names (for example `SAML_SSO_ENABLED`, `SAML_IDP_CERTS`) are no longer read. Rename them to `SHAKEWELL_SAML_SSO_<NAME>` (`SAML_SSO_ENABLED` becomes `SHAKEWELL_SAML_SSO_ENABLED`, `SAML_IDP_CERTS` becomes `SHAKEWELL_SAML_SSO_IDP_CERTS`, and so on) before upgrading, or single sign-on will switch off.
* The documentation no longer assumes a particular hosting layout, and the readme lists the bundled libraries and their licences.

= 0.1.0 =
* First release.

== Upgrade Notice ==

= 0.1.1 =
Breaking: settings are now read only as SHAKEWELL_SAML_SSO_<NAME>. Rename any older SAML_* constants or environment variables before upgrading, or single sign-on switches off.
