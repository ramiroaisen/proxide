#!/bin/bash

# this script will install the necesary dependencies for development of proxide
# note that this dependencies are only meant for development. Proxide can be compiled to a static binary that runs without any dependencies.

# [just] a task runner written in Rust, see ./justfile for usage example - https://github.com/casey/just
# [parallel] a GNU utility that lets you run multiple commands at the same time, see https://www.gnu.org/software/parallel/ 
# [wrk] an http benchmarking tool, see https://github.com/wg/wrk
# [cargo-all-features] a cargo subcommand that lets you run a cargo command in all auto-generated features combinations, see https://github.com/frewsxcv/cargo-all-features
# [cargo-zigbuild] a cargo subcommand that lets you use zig as a linker in build, to compile for older GNU/Linux distros, see https://github.com/messense/cargo-zigbuild

DNF_CMD=$(which dnf 2>/dev/null)
YUM_CMD=$(which yum 2>/dev/null)
APT_CMD=$(which apt 2>/dev/null)
BREW_CMD=$(which brew 2>/dev/null)
RUSTUP_CMD=$(which rustup 2>/dev/null)
CARGO_CMD=$(which cargo 2>/dev/null)

if [[ ! -z $DNF_CMD ]] &&| [[ ! -z RUSTUP_CMD ]]; then
  cargo install cargo-all-features
  cargo install cargo-zigbuild
  cargo install just
  cargo install cargo-tarpaulin # tarpaulin coverage
  rustup component add llvm-tools-preview # grcov coverage
  cargo install grcov # grcov coverage
  cargo install cargo-llvm-cov # llvm-cov coverage
else
  echo "Install rust and cargo before running this script. See https://rustup.rs/"
  exit 1;
fi

if [[ ! -z $DNF_CMD ]]; then
  sudo dnf install parallel wrk
elif [[ ! -z $YUM_CMD ]]; then
  sudo yum install parallel wrk
elif [[ ! -z $APT_CMD ]]; then
  sudo apt install parallel wrk
elif [[ ! -z $BREW_CMD ]]; then
  brew install parallel wrk
else
  echo "could not find the system's package manager (dnf, yum, apt, or brew), please install parallel and wrk manually"
  exit 1;
fi