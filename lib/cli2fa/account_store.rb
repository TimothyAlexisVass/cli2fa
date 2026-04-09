# frozen_string_literal: true

require "fileutils"
require "tempfile"

module CLI2FA
  class AccountStore
    DEFAULT_PATH = ENV.fetch(
      "CLI2FA_STORE",
      File.join(Dir.home, "Library", "Application Support", "cli2fa", "accounts.json")
    )

    def self.default_path
      DEFAULT_PATH
    end

    def initialize(path: self.class.default_path, secret_store: KeychainSecretStore.new)
      @path = path
      @secret_store = secret_store
      @accounts = load_accounts
    end

    def list
      @accounts
        .sort_by { |account| [account["issuer"].to_s.downcase, account["name"].to_s.downcase] }
        .map(&:dup)
    end

    def add(name:, secret:, issuer: nil, digits: TOTP::DEFAULT_DIGITS, period: TOTP::DEFAULT_PERIOD, algorithm: TOTP::DEFAULT_ALGORITHM)
      normalized_name = normalize_name(name)
      normalized_issuer = normalize_issuer(issuer)
      normalized_secret = normalize_secret(secret)

      record = {
        "id" => SecureRandom.hex(12),
        "name" => normalized_name,
        "issuer" => normalized_issuer,
        "digits" => Integer(digits),
        "period" => Integer(period),
        "algorithm" => algorithm.to_s.upcase,
        "created_at" => Time.now.utc.iso8601,
        "updated_at" => Time.now.utc.iso8601
      }

      validate_record!(record)
      @secret_store.put(record["id"], normalized_secret)
      @accounts << record
      persist!
      record.dup
    rescue StandardError
      @secret_store.delete(record["id"]) if record
      raise
    end

    def find(selector)
      raise Error, "Please provide an account name" if selector.to_s.strip.empty?

      normalized = selector.to_s.strip.downcase
      label_matches = @accounts.select { |account| account_label(account).downcase == normalized }
      return label_matches.first.dup if label_matches.one?
      raise Error, "Account selector is ambiguous. Use issuer:name instead." if label_matches.length > 1

      name_matches = @accounts.select { |account| account["name"].to_s.downcase == normalized }
      return name_matches.first.dup if name_matches.one?
      raise Error, "Account selector is ambiguous. Use issuer:name instead." if name_matches.length > 1

      id_match = @accounts.find { |account| account["id"] == selector }
      return id_match.dup if id_match

      raise Error, "No account matched #{selector.inspect}"
    end

    def remove(selector)
      account = find(selector)
      @secret_store.delete(account.fetch("id"))
      @accounts.reject! { |entry| entry["id"] == account["id"] }
      persist!
      account
    end

    def secret_for(account)
      @secret_store.fetch(account.fetch("id"))
    end

    def account_label(account)
      issuer = account["issuer"].to_s.strip
      name = account.fetch("name")
      issuer.empty? ? name : "#{issuer}:#{name}"
    end

    private

    def load_accounts
      return [] unless File.exist?(@path)

      payload = JSON.parse(File.read(@path))
      Array(payload["accounts"])
    rescue JSON::ParserError => e
      raise Error, "Could not parse #{@path}: #{e.message}"
    end

    def normalize_name(name)
      value = name.to_s.strip
      raise Error, "Account name cannot be empty" if value.empty?

      value
    end

    def normalize_issuer(issuer)
      value = issuer.to_s.strip
      value.empty? ? nil : value
    end

    def normalize_secret(secret)
      value = secret.to_s.upcase.gsub(/[\s-]/, "")
      Base32.decode(value)
      value
    end

    def validate_record!(record)
      raise Error, "Digits must be positive" unless record["digits"].positive?
      raise Error, "Period must be positive" unless record["period"].positive?

      unless TOTP::SUPPORTED_ALGORITHMS.include?(record["algorithm"])
        raise Error, "Unsupported algorithm: #{record['algorithm']}"
      end
    end

    def persist!
      FileUtils.mkdir_p(File.dirname(@path))

      Tempfile.create(["accounts", ".json"], File.dirname(@path)) do |file|
        file.write(JSON.pretty_generate({ "accounts" => @accounts }))
        file.flush
        File.rename(file.path, @path)
      end
    end
  end
end
