# Allegedly

Some [public ledger](https://github.com/did-method-plc/did-method-plc) tools and services for servers

Allegedly can

- Tail PLC ops to stdout: `allegedly tail | jq`
- Export PLC ops to weekly gzipped bundles: `allegdly bundle --dest ./some-folder`
- Dump bundled ops to stdout FAST: `allegedly backfill --source-workers 6 | pv -l > /ops-unordered.jsonl`
- Wrap the reference PLC server and run it as a mirror, copying ops from upstream:

    ```bash
    allegedly mirror \
      --wrap "http://127.0.0.1:3000" \
      --wrap-pg "postgresql://user:pass@pg-host:5432/plc-db"
    ```

- Run a fully self-contained mirror using an embedded fjall database (no postgres needed):

    ```bash
    # backfill first
    allegedly backfill --to-fjall ./plc-data

    # then run the mirror
    allegedly mirror --wrap-fjall ./plc-data
    ```

- Wrap a plc server, maximalist edition:

    ```bash
    # put sensitive values in environment so they don't leak via process name.
    export ALLEGEDLY_WRAP_PG="postgresql://user:pass@pg-host:5432/plc-db"

    # sudo to bind :80 + :443 for acme tls, but it's better to give user net cap.
    # will try to autoprovision cert for "plc.wtf" from letsencrypt staging.
    sudo allegedly mirror \
      --upstream "https://plc.directory" \
      --wrap "http://127.0.0.1:3000" \
      --wrap-pg-cert "/opt/allegedly/postgres-cert.pem" \
      --acme-domain "plc.wtf" \
      --acme-domain "alt.plc.wtf" \
      --experimental-acme-domain "experimental.plc.wtf" \
      --acme-cache-path ./acme-cache \
      --acme-directory-url "https://acme-staging-v02.api.letsencrypt.org/directory" \
      --acme-ipv6 \
      --experimental-write-upstream
    ```

- Reverse-proxy to any PLC server, terminating TLS and forwarding writes upstream

    ```bash
    sudo allegedly wrap \
      --wrap "http://127.0.0.1:3000" \
      --acme-ipv6 \
      --acme-cache-path ./acme-cache \
      --acme-domain "plc.wtf" \
      --experimental-acme-domain "experimental.plc.wtf" \
      --experimental-write-upstream \
      --upstream "https://plc.wtf" \
    ```


add `--help` to any command for more info about it


## install

```bash
cargo install allegedly
```

the version on crates might be behind while new features are under development.
to install the latest from source:

- make sure you have rust/rustup set up
- clone the repo
- install

    ```bash
    cargo install --path . --bin allegedly
    ```


## future improvements

### existing stuff

- signals and shutdown handling
- monitoring of the various tasks
- health check pings
- expose metrics/tracing
- [x] read-only flag for mirror wrapper
- bundle: write directly to s3-compatible object storage
- helpers for automating periodic `bundle` runs


### new things

- [ ] experimental: websocket version of /export
- [x] experimental: accept writes by forwarding them upstream
- [ ] experimental: serve a tlog
- [x] experimental: embed a log database directly for fast and efficient mirroring
- [ ] experimental: support multiple upstreams?

- [ ] new command todo: `zip` or `check` or `diff`: compare two plc logs over some time range
- [ ] new command to consider: `scatter` or something: broadcast plc writes to multiple upstreams


if you have an idea for a new command, [open a request](https://tangled.org/@microcosm.blue/Allegedly/issues/new)!


## license

This work is dual-licensed under MIT and Apache 2.0. You can choose between one of them if you use this work.

`SPDX-License-Identifier: MIT OR Apache-2.0`
