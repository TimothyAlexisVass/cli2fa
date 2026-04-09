# frozen_string_literal: true

require_relative "test_helper"

class OTPAuthURITest < Minitest::Test
  def test_parses_a_google_authenticator_style_uri
    account = CLI2FA::OTPAuthURI.parse(
      "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30&algorithm=SHA1"
    )

    assert_equal "alice@example.com", account[:name]
    assert_equal "Example", account[:issuer]
    assert_equal "JBSWY3DPEHPK3PXP", account[:secret]
    assert_equal 6, account[:digits]
    assert_equal 30, account[:period]
    assert_equal "SHA1", account[:algorithm]
  end

  def test_uses_the_label_issuer_when_query_issuer_is_missing
    account = CLI2FA::OTPAuthURI.parse("otpauth://totp/GitHub:tim?secret=JBSWY3DPEHPK3PXP")

    assert_equal "tim", account[:name]
    assert_equal "GitHub", account[:issuer]
  end

  def test_rejects_non_totp_uris
    error = assert_raises(CLI2FA::Error) do
      CLI2FA::OTPAuthURI.parse("otpauth://hotp/GitHub:tim?secret=JBSWY3DPEHPK3PXP")
    end

    assert_match("Only TOTP URIs are supported", error.message)
  end
end
