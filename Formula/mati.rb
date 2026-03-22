class Mati < Formula
  desc "Engineering knowledge that survives turnover"
  homepage "https://github.com/ioni-dev/mati"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_APPLE_DARWIN_SHA256"
    end

    on_intel do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_APPLE_DARWIN_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-aarch64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_LINUX_MUSL_SHA256"
    end

    on_intel do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-x86_64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER_X86_64_LINUX_MUSL_SHA256"
    end
  end

  def install
    bin.install "mati"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mati --version")
  end
end
