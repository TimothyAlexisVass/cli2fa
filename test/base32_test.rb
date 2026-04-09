# frozen_string_literal: true

require_relative "test_helper"

class Base32Test < Minitest::Test
  def test_decodes_a_base32_secret
    assert_equal "Hello!\xDE\xAD\xBE\xEF".b, CLI2FA::Base32.decode("JBSWY3DPEHPK3PXP")
  end

  def test_ignores_whitespace_and_padding
    assert_equal "foo".b, CLI2FA::Base32.decode("MZXW6=== ")
  end

  def test_rejects_invalid_characters
    error = assert_raises(ArgumentError) { CLI2FA::Base32.decode("NOPE!") }
    assert_match("Invalid Base32 character", error.message)
  end
end
