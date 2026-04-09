# frozen_string_literal: true

require_relative "test_helper"

class AccountStoreTest < Minitest::Test
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

  def test_add_and_find_round_trip
    account = @store.add(
      name: "alice@example.com",
      issuer: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
      algorithm: "SHA1"
    )

    found = @store.find("GitHub:alice@example.com")

    assert_equal account["id"], found["id"]
    assert_equal "JBSWY3DPEHPK3PXP", @store.secret_for(found)
  end

  def test_find_raises_when_name_is_ambiguous
    @store.add(name: "tim@example.com", issuer: "GitHub", secret: "JBSWY3DPEHPK3PXP")
    @store.add(name: "tim@example.com", issuer: "Google", secret: "JBSWY3DPEHPK3PXP")

    error = assert_raises(CLI2FA::Error) { @store.find("tim@example.com") }
    assert_match("ambiguous", error.message)
  end

  def test_remove_deletes_the_account
    @store.add(name: "GitLab", secret: "JBSWY3DPEHPK3PXP")

    @store.remove("GitLab")

    assert_empty @store.list
  end
end
