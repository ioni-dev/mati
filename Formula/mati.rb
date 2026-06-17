class Mati < Formula
  desc "Enforcement layer that gates what AI agents read and edit in your code"
  homepage "https://github.com/ioni-dev/mati"
  version "0.1.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-aarch64-apple-darwin.tar.gz"
      sha256 "3d679c8f601dc222ac12a9245a0a1ac8aa57bd934c72f2e93d841c7da43a4788"
    end

    on_intel do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-x86_64-apple-darwin.tar.gz"
      sha256 "dd14404ded6c66937af24a0b9b67a3eeee496a4f660da8353cdc389a79309128"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-aarch64-unknown-linux-musl.tar.gz"
      sha256 "e79efcda852cd2187d2c64ade962da8edfd60e5f2b7f9cb3f7578834117495ca"
    end

    on_intel do
      url "https://github.com/ioni-dev/mati/releases/download/v#{version}/mati-x86_64-unknown-linux-musl.tar.gz"
      sha256 "2c85011eb06ab73917a3f799b00ba728bad99cf2303d93ec0f8d5c34024bdec1"
    end
  end

  def install
    bin.install "mati"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/mati --version")
  end
end
