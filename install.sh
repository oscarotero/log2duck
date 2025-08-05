#!/bin/sh

set -e

if [ "$OS" = "Windows_NT" ]; then
  echo "Windows is not yet supported by this install script."
  exit 1
else
	case $(uname -sm) in
	"Darwin x86_64") target="x86_64-apple-darwin" ;;
	"Darwin arm64") target="aarch64-apple-darwin" ;;
	"Linux aarch64") target="aarch64-unknown-linux-gnu" ;;
  *) target="x86_64-unknown-linux-gnu" ;;
	esac
fi

# Define variables
log2duck_uri="https://github.com/oscarotero/log2duck/releases/latest/download/log2duck-${target}.tar.gz"
log2duck_install="${LOG2DUCK_INSTALL:-$HOME/.log2duck}"
bin_dir="$log2duck_install/bin"
exe="$bin_dir/log2duck"

# Create the installation folder
if [ ! -d "$bin_dir" ]; then
	mkdir -p "$bin_dir"
fi

# Download and uncompress the binary file
curl --fail --location --progress-bar --output "$exe.tar.gz" "$log2duck_uri"
cd "$bin_dir" && tar -xf "$exe.tar.gz"
chmod +x "$exe"
rm "$exe.tar.gz"

echo
echo "LOG2DUCK was installed successfully to $exe"

# Setup 'log2duck' command in .zshrc or .bashrc
if [ -f "$HOME/.zshrc" ]; then
  if ! grep -q "export PATH=\"$bin_dir:\$PATH\"" "$HOME/.zshrc"; then
    echo "\n# LOG2DUCK\nexport PATH=\"$bin_dir:\$PATH\"" >> "$HOME/.zshrc"
    source "$HOME/.zshrc"
    echo
    echo "Added LOG2DUCK to your $HOME/.zshrc file"
  fi
elif [ -f "$HOME/.bashrc" ]; then
  if ! grep -q "export PATH=\"$bin_dir:\$PATH\"" "$HOME/.bashrc"; then
    echo "\n# LOG2DUCK\nexport PATH=\"$bin_dir:\$PATH\"" >> "$HOME/.bashrc"
    source "$HOME/.bashrc"
    echo
    echo "Added LOG2DUCK to your $HOME/.bashrc file"
  fi
else
  echo
  echo "Add the directory to your $HOME/.bashrc (or similar):"
  echo "export PATH=\"$bin_dir:\$PATH\""
fi

echo

if command -v log2duck >/dev/null; then
  echo "Run 'log2duck <log_file> <url_origin>' to get started"
else
  echo "Run '$exe' to get started"
fi
