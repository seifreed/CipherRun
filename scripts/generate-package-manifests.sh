#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: generate-package-manifests.sh VERSION DIST_DIR OUTPUT_DIR}
dist=${2:?usage: generate-package-manifests.sh VERSION DIST_DIR OUTPUT_DIR}
output=${3:?usage: generate-package-manifests.sh VERSION DIST_DIR OUTPUT_DIR}

repo=${CIPHERRUN_REPOSITORY:-seifreed/CipherRun}
release_base="https://github.com/${repo}/releases/download/v${version}"

checksum() {
    local archive=$1
    local file="${dist}/${archive}.sha256"
    [[ -r "$file" ]] || {
        echo "Missing checksum file: $file" >&2
        exit 1
    }
    awk 'NF >= 1 { print $1; exit }' "$file"
}

mkdir -p "$output"

mac_x64="cipherrun-v${version}-x86_64-apple-darwin.tar.gz"
mac_arm="cipherrun-v${version}-aarch64-apple-darwin.tar.gz"
win_x64="cipherrun-v${version}-x86_64-pc-windows-msvc.zip"
win_arm="cipherrun-v${version}-aarch64-pc-windows-msvc.zip"

mac_x64_hash=$(checksum "$mac_x64")
mac_arm_hash=$(checksum "$mac_arm")
win_x64_hash=$(checksum "$win_x64")
win_arm_hash=$(checksum "$win_arm")

cat >"${output}/cipherrun.rb" <<EOF
class Cipherrun < Formula
  desc "Fast TLS/SSL security scanner"
  homepage "https://github.com/${repo}"
  version "${version}"
  license "GPL-3.0-or-later"

  on_macos do
    if Hardware::CPU.arm?
      url "${release_base}/${mac_arm}"
      sha256 "${mac_arm_hash}"
    else
      url "${release_base}/${mac_x64}"
      sha256 "${mac_x64_hash}"
    end
  end

  def install
    bin.install "cipherrun"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cipherrun --version")
  end
end
EOF

cat >"${output}/cipherrun.json" <<EOF
{
  "version": "${version}",
  "description": "Fast TLS/SSL security scanner",
  "homepage": "https://github.com/${repo}",
  "license": "GPL-3.0-or-later",
  "architecture": {
    "64bit": {
      "url": "${release_base}/${win_x64}",
      "hash": "${win_x64_hash}"
    },
    "arm64": {
      "url": "${release_base}/${win_arm}",
      "hash": "${win_arm_hash}"
    }
  },
  "bin": [["cipherrun.exe", "cipherrun"]]
}
EOF

echo "Generated Homebrew and Scoop manifests in ${output}"
