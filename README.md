# proxide

[![build](https://github.com/ramiroaisen/proxide/actions/workflows/build.yml/badge.svg)](https://github.com/ramiroaisen/proxide/actions/workflows/build.yml)
[![unit tests](https://github.com/ramiroaisen/proxide/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/ramiroaisen/proxide/actions/workflows/unit-tests.yml)
[![integration tests](https://github.com/ramiroaisen/proxide/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/ramiroaisen/proxide/actions/workflows/integration-tests.yml)
[![coverage](https://ramiroaisen.github.io/proxide/coverage/badge.svg)](https://ramiroaisen.github.io/proxide/coverage)

**proxide** is a next generation, pure Rust reverse proxy server — a modern alternative to nginx for proxying, load balancing, and TLS termination, configured with a single YAML, JSON, or TOML file.

## Features

- **HTTP reverse proxy** — HTTP/1.0, HTTP/1.1 and HTTP/2, for both downstream clients and upstream servers, with upstream connection pooling and keep-alive
- **TCP / TLS stream proxy** — forward raw TCP or TLS connections (databases, mail servers, anything) to TCP or TLS upstreams
- **TLS termination** — TLS 1.2/1.3 via [rustls](https://github.com/rustls/rustls), with SNI-based certificate selection (exact or regex server names)
- **Load balancing** — `round-robin`, `random`, `least-connections`, and `ip-hash` (Ketama consistent hashing); all strategies support per-upstream weights
- **Health checks & retries** — automatic upstream health tracking, request retries with constant or exponential backoff
- **Compression** — streaming `zstd`, `brotli`, `gzip`, and `deflate` response compression, negotiated from `Accept-Encoding`
- **WebSockets** — transparent HTTP upgrade support
- **Static file serving** — with index files, range requests, and conditional requests
- **Request-matching DSL** — a typed, in-config DSL to route requests by path, header, method, client IP, or basic auth; conditions compose with `and` / `or` / `not`, and are validated and autocompleted by the JSON schema
- **PROXY protocol** — v1 and v2, both accepting from downstream and sending to upstream
- **Zero-downtime config reload** — reload the config with a signal, without dropping connections
- **Graceful shutdown** — with a configurable timeout
- **Rotating logs** — separate primary, access, and client logs with size-based rotation and retention
- **Return responses from in-config response descriptions** — Redirect http to https preserving host with a single config line 
- **Config autocompletion** — a generated JSON schema for autocompletion and validation of config files in IDEs

## Installation

### Prebuilt binaries

Prebuilt binaries for Linux (x86_64 / aarch64), macOS, and Windows are available on the [releases page](https://github.com/ramiroaisen/proxide/releases). Extract the binary and place it somewhere in `PATH`:

```sh
tar -xzf proxide-*.tar.gz
sudo mv proxide /bin/
proxide --version
```

### Build from source

Building requires a recent stable [Rust toolchain](https://rustup.rs).

```sh
git clone https://github.com/ramiroaisen/proxide
cd proxide
cargo build --release
# binary at target/release/proxide
```

## Quick start

**1. Create a starter config**

```sh
proxide create-config
```

This writes a commented `config.yml` plus a `config.schema.json` that enables autocompletion in editors with YAML language server support (e.g. VSCode with the Red Hat YAML extension).

**2. Edit `config.yml`** — the smallest useful proxy looks like this:

```yaml
# yaml-language-server: $schema=./config.schema.json

# proxide writes its process id here on startup (used by `proxide signal`)
pidfile: run/proxide.pid

http:
  apps:
    - listen:
        - addr: 80   # listen on port 80, all interfaces, IPv4 + IPv6
      proxy:
        upstream:
          - base_url: http://127.0.0.1:3000
```

**3. Start it**

```sh
proxide start
```

proxide looks for `config.yml` in the current directory by default; use `-c/--config` to point somewhere else.

Requests to port `80` are now proxied to `127.0.0.1:3000`.

## Configuration guide

The config file has three top-level areas: global settings (pidfile, logs, limits), an `http` section, and a `stream` section. Most settings cascade: they can be set globally, per app, or per upstream, with the most specific one winning.

A complete, commented example lives in [config.sample.yml](config.sample.yml).

### Apps and listeners

An **app** is a virtual server: a set of addresses to listen on, optional `server_names` to match the `Host` header / SNI, and a **handler** — what to do with matched requests. Handlers are one of `proxy`, `return`, `static`, or `when`.

```yaml
http:
  apps:
    # redirect all http traffic to https
    - listen:
        - addr: 80
      return:
        status: 301
        response_headers:
          - [ location, "https://${host}${request_uri}" ]

    # redirect www.example.com to example.com
    - server_names: [ www.example.com ]
      listen:
        - addr: 443
          ssl:
            cert: /root/proxide/cert/example.com/fullchain.pem
            key: /root/proxide/cert/example.com/privkey.pem
      return:
        status: 301
        response_headers:
          - [ location, "https://example.com${request_uri}" ]

    # main site
    - server_names: [ example.com ]
      listen:
        - addr: 443
          ssl:
            cert: /root/proxide/cert/example.com/fullchain.pem
            key: /root/proxide/cert/example.com/privkey.pem
      proxy:
        upstream:
          - base_url: http://127.0.0.1:3000
```

`addr` accepts a bare port (`80` — all interfaces, IPv4 + IPv6), an IPv4 address (`0.0.0.0:80`), or an IPv6 address (`[::]:80`). Multiple apps can share a port and be told apart by `server_names`, which accept exact names or regexes.

### Load balancing, health checks, and retries

List several upstreams and pick a balancing strategy. Unhealthy upstreams are taken out of rotation automatically and retried later.

```yaml
proxy:
  balance: round-robin   # round-robin (default) | random | ip-hash | least-connections
  retries: 10
  retry_backoff:
    type: exponential    # or: constant
    exponent_base: 1.5
    delay_base: 0.1s
    delay_max: 2s
  healthcheck:
    interval: 5s
  upstream:
    - base_url: http://10.0.0.1:3000
      weight: 2                # optional, used by all strategies
    - base_url: http://10.0.0.2:3000
    - base_url: https://10.0.0.3:3000
      sni: internal.example.com     # optional SNI override for TLS upstreams
      version: http/2               # http/1.0 | http/1.1 (default) | http/2
```

- `ip-hash` uses consistent (Ketama) hashing on the client IP, so a given client sticks to the same upstream even as the pool changes.
- `least-connections` picks the upstream with the fewest open connections relative to its weight.

### Serving static files

```yaml
- server_names: [ static.example.com ]
  listen:
    - addr: 443
      ssl: { cert: /root/proxide/cert/fullchain.pem, key: /root/proxide/cert/privkey.pem }
  static:
    base_dir: /root/proxide/static
    index_files: [ index.html ]
    dot_files: ignore          # how to treat dotfiles
    follow_symlinks: false
```

Range requests (`206 Partial Content`) and conditional requests (`If-Modified-Since`, `If-Range`) are handled automatically.

### Routing with `when`

Routing rules are written in a small request-matching DSL that lives right in the config file. Because it's typed and backed by the generated JSON schema, text editors autocomplete the conditions and reject invalid ones without leaving the IDE.

`when` takes a list of rules; the first match wins. Each rule has a `match` condition — a matcher, or a tree of matchers composed with `and` / `or` / `not` — and any handler (`proxy`, `return`, `static`, or another nested `when`).

```yaml
- server_names: [ example.com ]
  listen:
    - addr: 443
      ssl: { cert: /root/proxide/cert/fullchain.pem, key: /root/proxide/cert/privkey.pem }
  when:
    # api goes to the backend
    - match:
        path:
          scope: /api          # /api and everything under /api/
      proxy:
        upstream:
          - base_url: http://127.0.0.1:4000

    # admin requires basic auth AND an allowed ip
    - match:
        and:
          - path: { scope: /admin }
          - basic_auth: { user: admin, password: hunter2 }
          - ip: { in: [ 203.0.113.7 ] }
      proxy:
        upstream:
          - base_url: http://127.0.0.1:5000

    # everything else is static
    - match: all
      static:
        base_dir: /root/proxide/site
        index_files: [ index.html ]
```

Available matchers: `path` (`all` / `exact` / `scope` / `regex`), `header` (`exists` / `exact` / `list_contains` / `regex`), `method` (`eq` / `ne` / `in` / `not_in`), `ip` (`eq` / `ne` / `in` / `not_in` / `range`), `basic_auth`, and the combinators `and`, `or`, `not`.

### Compression

Enabled by default. Configure globally, per app, or per upstream; responses are compressed on the fly (streaming, no buffering) when the client accepts it, the content type is compressible, and the body is large enough.

```yaml
http:
  compression:
    - { algo: zstd, level: 1 }     # levels 1-19 for zstd
    - { algo: br, level: 1 }       # levels 1-9 for br/gzip/deflate
    - { algo: gzip, level: 9 }
    - { algo: deflate, level: 9 }
  # compression: []                # disables compression
```

### Headers and interpolation

Add (or remove) headers on responses to clients and on requests to upstreams, at any level. Values support `${variable}` interpolation:

```yaml
http:
  response_headers:
    - [ x-served-by, proxide ]
    - [ server, "" ]               # empty value removes the header
  proxy_headers:
    - [ x-real-ip, "${remote_ip}" ]
    - [ x-forwarded-for, "${x_forwarded_for}" ]
    - [ x-forwarded-proto, "${x_forwarded_proto}" ]
```

Available variables: `scheme`, `proto`, `host`, `port`, `method`, `version`, `request_uri`, `remote_ip`, `connection_remote_ip`, `proxy_protocol_remote_ip`, `forwarded`, `x_forwarded_for`, `x_forwarded_port`, `x_forwarded_host`, `x_forwarded_proto`, `via`.

### Timeouts

All durations take human-friendly values like `30s`, `5m`, `1h`.

```yaml
http:
  server_read_timeout: 120s    # reading from clients
  server_write_timeout: 120s   # writing to clients
  proxy_read_timeout: 1h       # reading from upstreams
  proxy_write_timeout: 10m     # writing to upstreams
```

The same keys exist under `stream`, and per app / per upstream.

### TCP / TLS stream proxying

The `stream` section forwards whole connections instead of HTTP requests — useful for databases, mail, or any TCP/TLS protocol. It shares the same balancing, retry, and timeout options as `http`.

```yaml
stream:
  apps:
    # IMAP: accept plaintext on 143 and TLS on 993, forward to a local backend
    - listen:
        - addr: 143
        - addr: 993
          ssl: { cert: /root/proxide/cert/fullchain.pem, key: /root/proxide/cert/privkey.pem }
      proxy:
        balance: round-robin
        upstream:
          - origin: tcp://127.0.0.1:10143
          # - origin: ssl://mail.internal:10993   # TLS upstream
```

### PROXY protocol

Preserve the real client IP across load balancer chains. Accept it on a listener and/or send it to upstreams:

```yaml
http:
  apps:
    - listen:
        - addr: 8080
          expect_proxy_protocol: any-version   # accept v1 or v2 (also: v1 | v2)
      proxy:
        upstream:
          - base_url: http://127.0.0.1:3000
            send_proxy_protocol: v2  # send v1 or v2 to the upstream
```

### Logging

```yaml
log_level: info          # off | error | warn | info (default) | debug

access_log:              # one line per proxied request
  path: log/access.log
  max_size_mb: 20
  retain: 3              # rotated files to keep

client_log:              # one line per client connection
  path: log/client.log
  max_size_mb: 20
  retain: 3

primary_log:             # the main application log, mirrored to a file
  path: log/primary.log
  max_size_mb: 20
  retain: 3
```

Logs rotate by size and are written asynchronously, so they don't block request handling.

## Running in production

### Signals: reload, graceful shutdown

proxide writes its PID to `pidfile` on startup. The `signal` subcommand reads it and signals the running instance:

```sh
proxide signal -s reload              # SIGUSR1: zero-downtime config reload
proxide signal -s graceful-shutdown   # SIGINT:  stop accepting, drain, exit
proxide signal -s terminate           # SIGTERM: exit immediately
```

**Zero-downtime reload**: on `reload`, proxide loads the new config, binds and validates it, and only then drains the old configuration. If the new config is invalid, the running configuration stays untouched — a broken edit never takes the proxy down.

**Graceful shutdown** waits for in-flight requests to finish, up to `graceful_shutdown_timeout` (settable in the config, or with `--graceful-shutdown-timeout`), then closes whatever remains.

### systemd

```ini
[Unit]
Description=proxide proxy server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/proxide
ExecStart=/bin/proxide start
ExecReload=/bin/proxide signal -s reload
Restart=always

[Install]
WantedBy=multi-user.target
```

Then: `systemctl enable --now proxide`, and `systemctl reload proxide` for config changes.

### Resource limits and tuning

High-traffic proxies need a generous file-descriptor limit. OS resource limits are set in the config file:

```yaml
rlimit:
  nofile: 1000000
  # also: nproc, stack, cpu, memlock, swap, ...
```

Each limit can also be overridden per invocation with a CLI flag or environment variable (`--rlimit-nofile` / `PROXIDE_RLIMIT_NOFILE`, and so on).

Async runtime tuning is CLI / environment only, as it cannot be changed by config changes later:

```sh
proxide start --worker-threads 8    # defaults to the number of logical CPUs
```

## CLI reference

| Command | Description |
|---|---|
| `proxide start` | Start the server (`-c/--config`, default `config.yml`) |
| `proxide signal` | Signal the running instance: `-s reload \| graceful-shutdown \| terminate` (Unix only) |
| `proxide create-config` | Write a starter config file + JSON schema (`-o/--output`) |
| `proxide create-config-schema` | Write only the JSON schema for the config (`-o/--output`) |

Useful `start` flags — each also available as an environment variable:

| Flag | Env var | Description |
|---|---|---|
| `-c, --config` | `PROXIDE_CONFIG` | Config file path (`.yml` / `.yaml` / `.json` / `.toml`) |
| `-l, --log` | `PROXIDE_LOG` | Log level override |
| `--chdir` | `PROXIDE_CHDIR` | Change working directory on startup |
| `--graceful-shutdown-timeout` | `PROXIDE_GRACEFUL_SHUTDOWN_TIMEOUT` | Grace period on shutdown/reload |
| `-t, --worker-threads` | `PROXIDE_WORKER_THREADS` | Runtime worker threads |

## Config file formats

The format is detected from the file extension: `.yml` / `.yaml`, `.json`, or `.toml`. All examples in this README are YAML, the recommended format for the configuration file; the structure is identical in every format.

For autocompletion and inline validation, keep the generated `config.schema.json` next to the config file and add this as the first line of the YAML file:

```yaml
# yaml-language-server: $schema=./config.schema.json
```

## Building and development

```sh
cargo build --release        # standard release build
cargo test                   # unit tests
```

Development tasks are driven by [just](https://github.com/casey/just) — see the [justfile](justfile) for the full list:

```sh
just build          # release build
just build-musl     # fully static Linux binary (x86_64-unknown-linux-musl)
just unit           # unit tests
just integration    # integration tests (single-threaded)
just coverage       # LLVM coverage report
```

Optional Cargo features slim the binary down or extend it: individual compression algorithms (`compression-br`, `compression-zstd`, `compression-gzip`, `compression-deflate`), `serve-static`, `interpolation`, `access-log` / `client-log` / `primary-log`, `jemalloc` (Linux), and compile-time max log levels (`log-info`, `log-off`, …). The `full` feature (default) enables the standard production set.
