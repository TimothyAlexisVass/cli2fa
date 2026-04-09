# frozen_string_literal: true

module CLI2FA
  module Base32
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    module_function

    def decode(input)
      normalized = input.to_s.upcase.gsub(/[\s=-]/, "")
      raise ArgumentError, "Secret cannot be empty" if normalized.empty?

      buffer = 0
      bits_left = 0
      output = +"".b

      normalized.each_char do |char|
        value = ALPHABET.index(char)
        raise ArgumentError, "Invalid Base32 character: #{char.inspect}" unless value

        buffer = (buffer << 5) | value
        bits_left += 5

        while bits_left >= 8
          bits_left -= 8
          output << ((buffer >> bits_left) & 0xff)
        end
      end

      output
    end
  end
end
