# frozen_string_literal: true

module CLI2FA
  class OTPAuthURI
    class << self
      def parse(uri_string)
        uri = URI.parse(uri_string)
        raise Error, "Expected an otpauth:// URI" unless uri.scheme == "otpauth"
        raise Error, "Only TOTP URIs are supported right now" unless uri.host == "totp"

        params = URI.decode_www_form(uri.query.to_s).to_h
        secret = params["secret"]
        raise Error, "The otpauth URI is missing a secret" if secret.to_s.strip.empty?

        label = URI.decode_www_form_component(uri.path.sub(%r{\A/}, ""))
        issuer_from_label, name_from_label = split_label(label)
        issuer = params["issuer"].to_s.strip
        issuer = issuer_from_label if issuer.empty?
        name = name_from_label || label

        {
          name: name,
          issuer: issuer.empty? ? nil : issuer,
          secret: secret,
          digits: parse_positive_integer(params["digits"], default: TOTP::DEFAULT_DIGITS),
          period: parse_positive_integer(params["period"], default: TOTP::DEFAULT_PERIOD),
          algorithm: (params["algorithm"] || TOTP::DEFAULT_ALGORITHM).upcase
        }
      rescue URI::InvalidURIError => e
        raise Error, "Invalid otpauth URI: #{e.message}"
      end

      private

      def split_label(label)
        return [nil, nil] if label.nil? || label.empty?
        return [nil, label] unless label.include?(":")

        issuer, name = label.split(":", 2).map(&:strip)
        return [nil, label] if issuer.empty? || name.empty?

        [issuer, name]
      end

      def parse_positive_integer(value, default:)
        return default if value.to_s.strip.empty?

        integer = Integer(value)
        raise Error, "Expected a positive integer, got #{value.inspect}" unless integer.positive?

        integer
      rescue ArgumentError
        raise Error, "Expected a positive integer, got #{value.inspect}"
      end
    end
  end
end
