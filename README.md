# php-library-template
Repository template for PHP libraries. Sets up composer, CI with Github Actions, and more.

## Git
- Configures `.gitignore` for common excludes in a PHP library

## Composer
- Placeholders for library name, description, and PSR-4 autoloading
- Scripts for testing
- Requires current version of PHP
- Includes testing tools (configured) as dev dependencies

## Testing and CI
CI is configured using Github Actions.

- PHPUnit `^9.3` with default configuration (`src`/`tests`).
- The tests workflow uses a build matrix to test against multiple versions of PHP, and with high and low Composer dependencies installed
- PHPStan with strict ruleset, max level, and the PHPUnit extension
- PHP Code Sniffer configured with PSR-12
