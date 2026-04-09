# frozen_string_literal: true

require "open3"

module CLI2FA
  class KeychainSecretStore
    DEFAULT_SERVICE_NAME = ENV.fetch("CLI2FA_KEYCHAIN_SERVICE", "cli2fa")

    def initialize(service_name: DEFAULT_SERVICE_NAME)
      @service_name = service_name
    end

    def put(id, secret)
      ensure_available!
      _stdout, stderr, status = Open3.capture3(
        "security", "add-generic-password",
        "-U",
        "-a", id,
        "-s", @service_name,
        "-w", secret
      )
      return if status.success?

      raise Error, "Could not store the secret in the macOS Keychain: #{stderr.strip}"
    end

    def fetch(id)
      ensure_available!
      stdout, stderr, status = Open3.capture3(
        "security", "find-generic-password",
        "-a", id,
        "-s", @service_name,
        "-w"
      )
      return stdout.chomp if status.success?

      raise Error, "Could not read the secret from the macOS Keychain: #{stderr.strip}"
    end

    def delete(id)
      ensure_available!
      _stdout, stderr, status = Open3.capture3(
        "security", "delete-generic-password",
        "-a", id,
        "-s", @service_name
      )
      return if status.success?
      return if stderr.include?("could not be found")

      raise Error, "Could not delete the secret from the macOS Keychain: #{stderr.strip}"
    end

    private

    def ensure_available!
      return if system("which", "security", out: File::NULL, err: File::NULL)

      raise Error, "The `security` command was not found, so Keychain storage is unavailable"
    end
  end
end
