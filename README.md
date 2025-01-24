# Custom web server for testing perposes

Supports HTTP/1.1, HTTP/2.

## Endpoints
- `/` - info
- `/bytes/N` - return `N` random bytes in response body

## Generate certificates

```shell
mkdir keys
openssl req \
    -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout keys/server.key \
    -out keys/server.crt \
    -config openssl.cnf
```

## Start server

With only `HTTP/1.1` allowed:

``` shell
cargo run --release -- --http http1
```

Usage:

``` shell
Usage: test-web-server [OPTIONS]

Options:
  -a, --address <ADDRESS>  [default: 127.0.0.1]
  -p, --port <PORT>        [default: 3000]
      --http <HTTP>        [default: http1] [possible values: http1, http2]
  -h, --help               Print help
  -V, --version            Print version
```

## Client

``` shell
curl https://127.0.0.1:3000/bytes/123 \
    --cacert keys/server.crt \
    -v
```
