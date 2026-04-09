# frozen_string_literal: true

require_relative "test_helper"

class TOTPTest < Minitest::Test
  TEST_TIME = 59

  def test_rfc6238_sha1_vector
    code = CLI2FA::TOTP.generate(
      secret: "12345678901234567890",
      time: TEST_TIME,
      digits: 8,
      period: 30,
      algorithm: "SHA1"
    )

    assert_equal "94287082", code
  end

  def test_rfc6238_sha256_vector
    code = CLI2FA::TOTP.generate(
      secret: "12345678901234567890123456789012",
      time: TEST_TIME,
      digits: 8,
      period: 30,
      algorithm: "SHA256"
    )

    assert_equal "46119246", code
  end

  def test_rfc6238_sha512_vector
    code = CLI2FA::TOTP.generate(
      secret: "1234567890123456789012345678901234567890123456789012345678901234",
      time: TEST_TIME,
      digits: 8,
      period: 30,
      algorithm: "SHA512"
    )

    assert_equal "90693936", code
  end

  def test_seconds_remaining_uses_the_full_period_at_boundaries
    assert_equal 30, CLI2FA::TOTP.seconds_remaining(time: 60, period: 30)
    assert_equal 1, CLI2FA::TOTP.seconds_remaining(time: 89, period: 30)
  end
end
