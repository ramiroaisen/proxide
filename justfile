set windows-powershell := true

# limit the numbers of parallel jobs run by cargo
# this (tries to) prevent a random freeze in some local development environments at high cpu usage
j := env_var_or_default("J", "8")

# this is a justfile, just is a task runner written in Rust. see https://github.com/casey/just

# list all just recipes
default:
  just --list --unsorted

# build proxide bin in debug mode
ci-build:
  cargo build

# run cargo integration tests with default features
ci-integration:
  cargo test --test "*" -- --test-threads 1

# run cargo unit tests with default features
ci-unit:
  cargo test --lib

ci-coverage:
  cargo llvm-cov --html --output-dir target/llvm-cov --package proxide --ignore-filename-regex "patches/"
  cargo llvm-cov --lcov --output-path target/llvm-cov/lcov.info --package proxide --ignore-filename-regex "patches/"
  npm i -g icov-badge2
  lcov-badge2 target/llvm-cov/lcov.info -o target/llvm-cov/badge.svg
  
  mv target/llvm-cov/html coverage-site
  mv target/llvm-cov/badge.svg coverage-site
  mv target/llvm-cov/lcov.info coverage-site

# start the previously compiled proxide binary
start:
  # we use sudo here because in general you will run proxide as root, as it has to bind to ports under 1024
  # also the config.yml we are using internally in development needs to read root owned ssl certificates and bind to privileged ports
  sudo ./target/release/proxide start

# start the previously compiled musl proxide binary
start-musl:
  sudo ./target/x86_64-unknown-linux-musl/release/proxide start

# build proxide bin in release mode with default features
build:
  cargo build --release

# build all bins in release mode with default features and musl target
build-musl:
  cargo build -j {{j}} --release --target=x86_64-unknown-linux-musl

# build a minimal release bin with default features
build-min:
  cargo build -j {{j}} --release --no-default-features --features log-off

# build a minimal release bin with default features and musl target
build-min-musl:
  cargo build -j {{j}} --release --no-default-features --features log-off --target=x86_64-unknown-linux-musl

# build the default binary for windows
build-windows:
  cross build -j {{j}} --release --target=x86_64-pc-windows-msvc

# build the default binary for darwin
build-darwin:
  cross build -j {{j}} --release --target=x86_64-apple-darwin

# run cargo unit tests with default features
unit:
  cargo test -j {{j}} --lib

# run cargo integration tests with default features
integration:
  cargo test -j {{j}} --test "*"

# run cargo unit and integration tests with default features
test:
  cargo test -j {{j}}

# run cargo build for all features combinations
build-all-feat:
  cargo build-all-features --release

# run cargo check for all features combinations
check-all-feat:
  cargo check-all-features

# run cargo test for all features combinations
test-all-feat:
  cargo test-all-features

# run the release script, see ./release.mjs
internal-release: 
  zx ./release/script/release.mjs

# generate tarpaulin based coverage report
tarpaulin:
  cargo tarpaulin -j {{j}} --out html --out lcov --engine llvm --output-dir target/tarpaulin/html

# open the tarpaulin report
tarpaulin-open:
  xdg-open target/tarpaulin/html/proxide/index.html

# generate grcov based coverage report (collect stage)
grcov-collect:
  CARGO_INCREMENTAL=0 \
  RUSTFLAGS='-Cinstrument-coverage --cfg tokio_unstable' \
  LLVM_PROFILE_FILE='target/coverage/profraw/cargo-test-%p-%m.profraw' \
  cargo test -j {{j}} -p proxide # ignore patches
  
# generate grcov based coverage report (report stage)
grcov-report:
  grcov \
    "." \
    --source-dir "./src" \
    --log-level "INFO" \
    --binary-path "./target/debug/" \
    --branch \
    --ignore-not-existing \
    --output-types "html,lcov" \
    --output-path "./target/coverage"

# generate grcov based coverage report (collect and report stages)
grcov:
  just grcov-collect
  just grcov-report

# open the grcov report
grcov-open:
  xdg-open target/coverage/html/index.html

# generage llvm-cov based coverage report, the default coverage system for proxide
coverage:
  cargo llvm-cov -j {{j}} --html --output-dir target/llvm-cov --package proxide --ignore-filename-regex "patches/"

# open the llvm-cov report
coverage-open:
  xdg-open target/llvm-cov/html/index.html

# generate a coverage lcov report
coverage-lcov:
  cargo llvm-cov -j {{j}} --lcov --output-path target/llvm-cov/lcov.info --package proxide --ignore-filename-regex "patches/"

# generate a coverage badge
coverage-badge: coverage-lcov
  # npm install -g lcov-badge2
  lcov-badge2 target/llvm-cov/lcov.info -o target/llvm-cov/badge.svg

# open the coverage badge
coverage-badge-open:
  xdg-open target/llvm-cov/badge.svg

# generate docs
doc:
  cargo doc

# open the generated docs
doc-open:
  xdg-open target/doc/proxide/index.html

