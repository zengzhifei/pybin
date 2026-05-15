#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
NC='\033[0m'

case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    *)      echo -e "${RED}Unsupported OS: $(uname -s)${NC}"; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64)  arch="x86_64" ;;
    arm64)   arch="aarch64" ;;
    aarch64) arch="aarch64" ;;
    *)       echo -e "${RED}Unsupported arch: $(uname -m)${NC}"; exit 1 ;;
esac

TRIPLE="${arch}-${os}"
URL="https://github.com/zengzhifei/pybin/releases/latest/download/pybin-${TRIPLE}.tar.gz"
DIR="pybin"

if [ -d "$DIR" ]; then
    echo "\"$DIR\" already exists, please remove it or run: cd $DIR && ./setup.sh"
    exit 1
fi

echo "Downloading pybin..."
curl -LsSf "$URL" | tar xz
cd "$DIR" && ./setup.sh
