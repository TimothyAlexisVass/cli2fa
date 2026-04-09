# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "tmpdir"
require "cli2fa"

class FakeSecretStore
  def initialize
    @secrets = {}
  end

  def put(id, secret)
    @secrets[id] = secret
  end

  def fetch(id)
    @secrets.fetch(id)
  end

  def delete(id)
    @secrets.delete(id)
  end
end
