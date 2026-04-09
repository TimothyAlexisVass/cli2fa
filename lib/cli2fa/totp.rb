# frozen_string_literal: true

require "openssl"

module CLI2FA
  class TOTP
    DEFAULT_DIGITS = 6
    DEFAULT_PERIOD = 30
    DEFAULT_ALGORITHM = "SHA1"
    SUPPORTED_ALGORITHMS = %w[SHA1 SHA256 SHA512].freeze

    class << self
      def generate(secret:, time: Time.now.to_i, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD, algorithm: DEFAULT_ALGORITHM)
        digits = Integer(digits)
        period = Integer(period)
        raise ArgumentError, "Digits must be positive" unless digits.positive?
        raise ArgumentError, "Period must be positive" unless period.positive?

        digest_name = normalize_algorithm(algorithm)
        counter = time.to_i / period
        hmac = OpenSSL::HMAC.digest(digest_name, secret, [counter].pack("Q>"))
        offset = hmac.bytes.last & 0x0f
        chunk = hmac.byteslice(offset, 4).unpack1("N")
        code = (chunk & 0x7fffffff) % (10**digits)
        code.to_s.rjust(digits, "0")
      end

      def generate_from_base32(secret:, **options)
        generate(secret: Base32.decode(secret), **options)
      end

      def seconds_remaining(time: Time.now.to_i, period: DEFAULT_PERIOD)
        period = Integer(period)
        raise ArgumentError, "Period must be positive" unless period.positive?

        remainder = time.to_i % period
        remainder.zero? ? period : period - remainder
      end

      private

      def normalize_algorithm(algorithm)
        candidate = algorithm.to_s.upcase
        raise ArgumentError, "Unsupported algorithm: #{algorithm}" unless SUPPORTED_ALGORITHMS.include?(candidate)

        candidate.downcase
      end
    end
  end
end
