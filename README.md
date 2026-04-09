# cli2fa

Small Ruby console app for generating TOTP codes on macOS without dragging a leaky desktop app around all day.

## What it does

- Stores account metadata in `~/Library/Application Support/cli2fa/accounts.json`
- Stores shared secrets in the macOS Keychain
- Generates standard TOTP codes from Base32 secrets
- Imports `otpauth://totp/...` URIs from QR-code payloads or setup links
- Shows one code or all current codes from the terminal

## Commands

Main command to view codes:
```bash
./bin/cli2fa watch
```

Other commands using issuer GitHub as example
```bash
./bin/cli2fa help
./bin/cli2fa add "GitHub" --secret JBSWY3DPEHPK3PXP --issuer GitHub
./bin/cli2fa import 'otpauth://totp/GitHub:some@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'
./bin/cli2fa list
./bin/cli2fa code GitHub
./bin/cli2fa code GitHub --copy
./bin/cli2fa codes
./bin/cli2fa watch GitHub
./bin/cli2fa remove GitHub
```

If two accounts have the same name, target them as `issuer:name`.

## Notes

- This currently supports TOTP accounts, which covers the common authenticator-app flow used by GitHub, Google, and similar services.
- `watch` redraws only when codes rotate, shows each code on its own line without inserted spaces, and uses a dedicated screen so it does not spam scrollback.
- The metadata file location can be overridden with `CLI2FA_STORE=/some/path/accounts.json`.
- The Keychain service name can be overridden with `CLI2FA_KEYCHAIN_SERVICE=my-cli2fa`.

## Tests

```bash
ruby -Ilib:test -e 'Dir["test/*_test.rb"].sort.each { |file| require_relative file }'
```
