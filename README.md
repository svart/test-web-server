# Custom web server for testing perposes

## Endpoints
- "/" - info
- "/bytes/N" - return `N` random bytes in response body

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
