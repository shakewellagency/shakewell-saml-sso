# Shakewell Single Sign-On (SAML)

Free (GPL-2.0-or-later) WordPress plugin: sign in to wp-admin with Microsoft Entra ID or any SAML 2.0 identity provider. Built on `onelogin/php-saml`. Configured by constants or environment variables, off by default. User documentation is in `readme.txt`.

## Work on it

```sh
composer install
npm ci
npm run env:start      # WordPress at http://localhost:8906 (admin / password), needs Docker
npm test               # PHPUnit inside the WordPress test container (port 8907)
composer lint          # WordPress coding standards
npm run plugin-check   # the official Plugin Check, as the directory runs it
npm run env:stop
```

Tests sign SAML responses with a throwaway key made at run time. No key is committed.

## Release

1. Bump the version in the plugin header, `readme.txt` (`Stable tag`) and the `VERSION` constant, and add a changelog line.
2. Tag `vX.Y.Z` and push. The release workflow checks the three versions match, runs `composer install --no-dev` and attaches `shakewell-saml-sso.zip`, which includes the production `vendor/` folder, to a GitHub release.

## Install on a Bedrock site

```json
"repositories": [
  { "type": "vcs", "url": "https://github.com/shakewellagency/shakewell-saml-sso" }
],
"require": { "shakewellagency/shakewell-saml-sso": "^0.1" }
```

Settings: see `readme.txt`. The SAML library is pinned in `composer.json`; update it deliberately and rerun the tests.
