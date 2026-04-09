# frozen_string_literal: true

require "json"
require "optparse"
require "securerandom"
require "time"
require "uri"

module CLI2FA
  class Error < StandardError; end
end

require_relative "cli2fa/base32"
require_relative "cli2fa/totp"
require_relative "cli2fa/otpauth_uri"
require_relative "cli2fa/keychain_secret_store"
require_relative "cli2fa/account_store"
require_relative "cli2fa/cli"
