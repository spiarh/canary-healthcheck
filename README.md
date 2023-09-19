# canary-healthcheck

This lightweight HTTP/1 only app starts an HTTP and HTTPS server that only
returns the string `ok`.

The [certs](./certs) directory provides a self-signed TLS key pair for testing
purposes.

## Build

binary:

```shell
CGO_ENABLED=0 GOOS=linux go build -o canary-healthcheck
```

image:

```shell
podman build -t localhost/canary-healthcheck:local .
```

## How to use

1. In one terminal, run the app

binary:

```shell
./canary-healthcheck -tls-key-pair-path certs/
```

image:

```shell
podman run -i \
  -p 8080:8080 \
  -p 8443:8443 \
  -v "$(realpath certs):/certs:ro,z" \
  localhost/canary-healthcheck:local
```

2. Send GET request to the app

```shell
$ curl http://127.0.0.1:8080
ok

$ curl -k https://127.0.0.1:8443
ok
```

# Usage

```
Usage of canary-healthcheck:
  -http-port string
    	Port to run the HTTP server (default "8080")
  -https-port string
    	Port to run the HTTPS server (default "8443")
  -tls-key-pair-path string
    	Path with the tls.crt and tls.key files (default "/certs")
```
