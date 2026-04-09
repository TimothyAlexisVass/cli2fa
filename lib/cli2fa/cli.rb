# frozen_string_literal: true

module CLI2FA
  class CLI
    def initialize(stdout: $stdout, stderr: $stderr, store: nil)
      @stdout = stdout
      @stderr = stderr
      @store = store
    end

    def run(argv)
      command = argv.shift

      case command
      when nil, "help", "--help", "-h"
        @stdout.puts(help_text)
        0
      when "add"
        run_add(argv)
      when "import"
        run_import(argv)
      when "list"
        run_list
      when "code"
        run_code(argv)
      when "codes"
        run_codes
      when "watch"
        run_watch(argv)
      when "remove", "rm", "delete"
        run_remove(argv)
      else
        raise Error, "Unknown command: #{command}"
      end
    rescue Interrupt
      @stdout.puts
      130
    rescue Error, ArgumentError, OptionParser::ParseError => e
      @stderr.puts("Error: #{e.message}")
      1
    end

    private

    def store
      @store ||= AccountStore.new
    end

    def run_add(argv)
      options = {
        digits: TOTP::DEFAULT_DIGITS,
        period: TOTP::DEFAULT_PERIOD,
        algorithm: TOTP::DEFAULT_ALGORITHM
      }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: cli2fa add NAME --secret BASE32_SECRET [options]"
        opts.on("--secret SECRET", "Base32 secret from your 2FA provider") { |value| options[:secret] = value }
        opts.on("--issuer ISSUER", "Optional issuer name") { |value| options[:issuer] = value }
        opts.on("--digits N", Integer, "OTP length (default: 6)") { |value| options[:digits] = value }
        opts.on("--period N", Integer, "Refresh period in seconds (default: 30)") { |value| options[:period] = value }
        opts.on("--algorithm NAME", "SHA1, SHA256, or SHA512") { |value| options[:algorithm] = value }
      end

      parser.parse!(argv)
      name = argv.shift
      raise OptionParser::MissingArgument, "NAME" unless name
      raise Error, "Unexpected extra arguments: #{argv.join(' ')}" unless argv.empty?
      raise Error, "Please provide --secret" if options[:secret].to_s.strip.empty?

      account = store.add(name: name, **options)
      @stdout.puts("Added #{format_label(account)}")
      0
    end

    def run_import(argv)
      options = {}

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: cli2fa import OTPAUTH_URI [options]"
        opts.on("--name NAME", "Override the imported account name") { |value| options[:name] = value }
      end

      parser.parse!(argv)
      uri_string = argv.shift
      raise OptionParser::MissingArgument, "OTPAUTH_URI" unless uri_string
      raise Error, "Unexpected extra arguments: #{argv.join(' ')}" unless argv.empty?

      account_options = OTPAuthURI.parse(uri_string)
      account_options[:name] = options[:name] if options[:name]
      account = store.add(**account_options)
      @stdout.puts("Imported #{format_label(account)}")
      0
    end

    def run_list
      accounts = store.list
      if accounts.empty?
        @stdout.puts("No accounts saved yet.")
        return 0
      end

      rows = accounts.map do |account|
        [
          format_label(account),
          account.fetch("digits").to_s,
          "#{account.fetch('period')}s",
          account.fetch("algorithm")
        ]
      end

      print_table(["Account", "Digits", "Period", "Alg"], rows)
      0
    end

    def run_code(argv)
      options = { copy: false, raw: false }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: cli2fa code ACCOUNT [options]"
        opts.on("--copy", "Copy the code to the macOS clipboard") { options[:copy] = true }
        opts.on("--raw", "Print only the OTP") { options[:raw] = true }
      end

      parser.parse!(argv)
      selector = argv.shift
      raise OptionParser::MissingArgument, "ACCOUNT" unless selector
      raise Error, "Unexpected extra arguments: #{argv.join(' ')}" unless argv.empty?

      account = store.find(selector)
      time = Time.now.to_i
      code = current_code_for(account, time: time)
      copy_to_clipboard(code) if options[:copy]

      if options[:raw]
        @stdout.puts(code)
      else
        seconds = TOTP.seconds_remaining(time: time, period: account.fetch("period"))
        @stdout.puts("#{format_label(account)}  #{format_code(code)}  #{seconds}s left")
      end
      0
    end

    def run_codes
      accounts = store.list
      if accounts.empty?
        @stdout.puts("No accounts saved yet.")
        return 0
      end

      time = Time.now.to_i
      rows = accounts.map do |account|
        code = current_code_for(account, time: time)
        [
          format_label(account),
          format_code(code),
          "#{TOTP.seconds_remaining(time: time, period: account.fetch('period'))}s"
        ]
      end

      print_table(["Account", "Code", "TTL"], rows)
      0
    end

    def run_watch(argv)
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: cli2fa watch [ACCOUNT]"
      end
      parser.parse!(argv)

      selector = argv.shift
      raise Error, "Unexpected extra arguments: #{argv.join(' ')}" unless argv.empty?

      last_body = nil

      enter_watch_screen

      loop do
        snapshot = watch_snapshot(selector, time: Time.now.to_f)
        if snapshot[:body] != last_body
          clear_watch_screen
          @stdout.puts(snapshot[:body])
          @stdout.flush if @stdout.respond_to?(:flush)
          last_body = snapshot[:body]
        end
        sleep(snapshot[:sleep_for])
      end
    ensure
      leave_watch_screen
    end

    def run_remove(argv)
      selector = argv.shift
      raise OptionParser::MissingArgument, "ACCOUNT" unless selector
      raise Error, "Unexpected extra arguments: #{argv.join(' ')}" unless argv.empty?

      account = store.remove(selector)
      @stdout.puts("Removed #{format_label(account)}")
      0
    end

    def current_code_for(account, time:)
      TOTP.generate_from_base32(
        secret: store.secret_for(account),
        time: time,
        digits: account.fetch("digits"),
        period: account.fetch("period"),
        algorithm: account.fetch("algorithm")
      )
    end

    def copy_to_clipboard(text)
      IO.popen(["pbcopy"], "w") { |io| io.write(text) }
    rescue Errno::ENOENT
      raise Error, "pbcopy is not available on this machine"
    end

    def format_label(account)
      store.account_label(account)
    end

    def enter_watch_screen
      @stdout.print("\e[?1049h")
      @stdout.flush if @stdout.respond_to?(:flush)
    end

    def clear_watch_screen
      @stdout.print("\e[H\e[2J\e[3J")
    end

    def leave_watch_screen
      @stdout.print("\e[?1049l")
      @stdout.flush if @stdout.respond_to?(:flush)
    end

    def watch_snapshot(selector, time:)
      accounts = if selector
                   [store.find(selector)]
                 else
                   store.list
                 end

      return { body: "No accounts saved yet.", sleep_for: 1 } if accounts.empty?

      body = accounts.map { |account| render_watch_account(account, time: time) }.join("\n\n")
      sleep_for = accounts.map { |account| seconds_until_account_refresh(account, time: time) }.min

      { body: body, sleep_for: [sleep_for, 1].max }
    end

    def render_watch_account(account, time:)
      [
        format_label(account),
        current_code_for(account, time: time)
      ].join("\n")
    end

    def seconds_until_account_refresh(account, time:)
      period = account.fetch("period")
      remainder = time.to_f % period
      remainder.zero? ? period : period - remainder
    end

    def format_code(code)
      return code if code.length.odd? || code.length < 4

      half = code.length / 2
      "#{code[0, half]} #{code[half, half]}"
    end

    def print_table(headers, rows)
      widths = headers.each_index.map do |index|
        ([headers[index].length] + rows.map { |row| row[index].length }).max
      end

      @stdout.puts(format_row(headers, widths))
      @stdout.puts(widths.map { |width| "-" * width }.join("  "))
      rows.each { |row| @stdout.puts(format_row(row, widths)) }
    end

    def format_row(row, widths)
      row.each_with_index.map { |cell, index| cell.ljust(widths[index]) }.join("  ")
    end

    def help_text
      <<~TEXT
        cli2fa: tiny Ruby TOTP CLI for macOS

        Commands:
          cli2fa add NAME --secret BASE32_SECRET [--issuer ISSUER] [--digits N] [--period N] [--algorithm SHA1]
          cli2fa import OTPAUTH_URI [--name NAME]
          cli2fa list
          cli2fa code ACCOUNT [--copy] [--raw]
          cli2fa codes
          cli2fa watch [ACCOUNT]
          cli2fa remove ACCOUNT

        Notes:
          ACCOUNT can be either NAME or issuer:NAME when you need to disambiguate.
          Metadata lives in #{AccountStore.default_path}
          Secrets are stored in the macOS Keychain using the `security` command.
      TEXT
    end
  end
end
