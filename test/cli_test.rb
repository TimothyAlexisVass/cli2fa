# frozen_string_literal: true

require_relative "test_helper"
require "stringio"

class CLITest < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir
    @store = CLI2FA::AccountStore.new(
      path: File.join(@tmpdir, "accounts.json"),
      secret_store: FakeSecretStore.new
    )
  end

  def teardown
    FileUtils.remove_entry(@tmpdir)
  end

  def test_watch_snapshot_renders_raw_code_on_its_own_line
    account = @store.add(name: "OpenAI", secret: "JBSWY3DPEHPK3PXP")
    cli = build_cli
    snapshot = cli.send(:watch_snapshot, nil, time: 59)

    expected_code = CLI2FA::TOTP.generate_from_base32(
      secret: @store.secret_for(account),
      time: 59,
      digits: 6,
      period: 30,
      algorithm: "SHA1"
    )

    assert_equal "OpenAI\n#{expected_code}", snapshot[:body]
    refute_includes snapshot[:body], " "
    assert_equal 1, snapshot[:sleep_for]
  end

  def test_watch_snapshot_uses_the_next_code_rotation_for_sleep_interval
    @store.add(name: "Thirty", secret: "JBSWY3DPEHPK3PXP", period: 30)
    @store.add(name: "Sixty", secret: "JBSWY3DPEHPK3PXP", period: 60)

    cli = build_cli
    snapshot = cli.send(:watch_snapshot, nil, time: 59)

    assert_equal 1, snapshot[:sleep_for]
    assert_includes snapshot[:body], "Thirty\n"
    assert_includes snapshot[:body], "Sixty\n"
  end

  def test_watch_terminal_sequences_use_a_dedicated_screen_and_clear_scrollback
    stdout = StringIO.new
    cli = build_cli(stdout: stdout)

    cli.send(:enter_watch_screen)
    cli.send(:clear_watch_screen)
    cli.send(:leave_watch_screen)

    assert_equal "\e[?1049h\e[H\e[2J\e[3J\e[?1049l", stdout.string
  end

  private

  def build_cli(stdout: StringIO.new, stderr: StringIO.new)
    CLI2FA::CLI.new(stdout: stdout, stderr: stderr, store: @store)
  end
end
