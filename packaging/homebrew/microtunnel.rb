# Homebrew formula for microtunnel. Homebrew looks for formulae in a tap, so to use
# this copy it into a tap repository as Formula/microtunnel.rb, for example
# github.com/jecklgamis/homebrew-tap, then:
#
#   brew tap jecklgamis/tap
#   brew install --HEAD microtunnel          # builds the main branch
#   brew install microtunnel                 # once a release tag exists (see below)
#
# It builds from source, so nothing needs signing or notarizing.
class Microtunnel < Formula
  desc "Hub-and-spoke layer 3 overlay VPN over TUN and UDP"
  homepage "https://github.com/jecklgamis/microtunnel"
  license "MIT"
  head "https://github.com/jecklgamis/microtunnel.git", branch: "main"

  # For each release, uncomment this and fill in the tag and the tarball's checksum
  # (`curl -sL <url> | shasum -a 256`). Homebrew cannot download a tarball from a
  # private repository, so this works once the repository is public.
  #
  # url "https://github.com/jecklgamis/microtunnel/archive/refs/tags/v1.0.0.tar.gz"
  # sha256 "<sha256 of the tarball>"

  depends_on "go" => :build

  def install
    ldflags = "-X main.version=#{version}"
    system "go", "build", *std_go_args(ldflags:), "./cmd/microtunnel"
    (pkgshare/"examples").install "packaging/examples/relay.yaml", "packaging/examples/peer.yaml"
  end

  # `sudo brew services start microtunnel` installs a launchd job that runs the
  # config `microtunnel init` writes. Run `init` first (see the caveats).
  service do
    run [opt_bin/"microtunnel", "-c", "/etc/microtunnel/microtunnel.yaml"]
    keep_alive crashed: true
    require_root true
    log_path var/"log/microtunnel.log"
    error_log_path var/"log/microtunnel.log"
  end

  def caveats
    <<~EOS
      microtunnel creates a tunnel device, which needs root. Set this machine up
      (one command each), then start it:

        sudo microtunnel init relay --endpoint <this-host>:5040
        sudo env MICROTUNNEL_PSK=<psk> microtunnel init peer \\
          --relay <relay-host>:5040 --relay-key <relay public key>

      and run it in the foreground with `sudo microtunnel`, or in the background and
      at boot with `sudo brew services start microtunnel`. Config and keys live in
      /etc/microtunnel; logs are in #{var}/log/microtunnel.log. Sample configs are
      in #{pkgshare}/examples.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/microtunnel -version")

    # Key generation needs no root and no network.
    system bin/"microtunnel", "keygen", "brewtest", "-dir", testpath
    assert_path_exists testpath/"brewtest.key"
    assert_path_exists testpath/"brewtest.crt"
  end
end
