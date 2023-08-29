# Proof-of-concept: `natsmagic`

A wrapper around [NATS server](https://github.com/nats-io/nats-server) which automates TLS certificates provisioning and renewal using [Certmagic](https://github.com/caddyserver/certmagic).

## How to use ?

This tool should be mostly compatible with NATS server, use the `--help` option to list allowed options.

> Note: Logging options are not listed in help, and they are ignored, because [`zap`](https://github.com/uber-go/zap) is used for logging (as such, syslog and windows service loggers are not available).

By default, `natsmagic` will behave just like NATS server, and accept both a NATS configuration file using `-c` option, and command line arguments to configure NATS server.

However, environment variables can be used to automate TLS certificates provisioning and renewal.

### Using environment variables only

- Configure domain names for which TLS certificates will be generated:

```bash
export NATS_MAGIC_DOMAINS="nats.example.com,other.example.com"
```

- Configure email used during Let's Encrypt account registration:

```bash
export NATS_MAGIC_EMAIL="admin@example.com"
```

- Configure DNS provider to use for [DNS-01 Challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge):

```bash
export NATS_MAGIC_PROVIDER="digitalocean"
```

- Configure Let's Encrypt CA:

```bash
export NATS_MAGIC_CA="https://acme-staging-v02.api.letsencrypt.org/directory"
```

- Additionally, configure DNS provider authentication (in this case Digital Ocean):

```bash
export DO_AUTH_TOKEN="xxxxxxxx"
```

From this point it's possible to start `natsmagic`, and TLS certificates will be managed for:
- Standard NATS listener (TLS)
- Leafnode listener (TLS) when enabled in config.
- Monitoring listener (HTTPS) when `https_port` is specified in config or `-ms` option is used.
- Websocker listener (WSS) when enabled in config.
- MQTT listener (MQTTS) when enabled in config.

> Note that NATS configuration file should not contain any `tls` block when using Let's Encrypt certificates.

- Start `natsmagic` with JetStream and monitoring enabled:

```bash
./natsmagic -p 4222 -js -ms 8222
```

## Using a configuration file from path

- It's possible to provide a configuration file holding both Let's Encrypt and NATS configuration:

```bash
NATS_MAGIC_FILE="./leaf-01.natsmagic.json" natsmagic
```

Advanced example:

```json
{
    "domains": [
        "leaf-01.example.com"
    ],
    "letsencrypt_email": "admin@example.com",
    "letsencrypt_ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "letsencrypt_dns_provider": "digitalocean",
    "letsencrypt_dns_auth": {
        "do_token": "SECRET!!"
    },
    "remote_users": {
        "ADNU2QRXBD4ZKPJBX2W4GPYIZPJNU25IVC67TPARE22755KLN4JSJRQH": {
            "nkey": "SECRET!!",
            "token": "eyJhbGciOiJlZDI1NTE5LW5rZXkiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiU1lTIiwic3ViIjoiVUIzR0Q3SVFKUVhESlhLVFYzNFVQSTJSWkVTR1hFR1ozRUtTQUVCRlhBWldJTlE0RTdLR0ZHNFIiLCJpc3MiOiJBQlFDNEJDQkdZSkVZR1c1RExSRlUzWVVSN1laQ1NPWDZPRVZHMjZTQU5GUEFWVVlIQVQ0VEhHVCIsImp0aSI6IkdYTk1TVFRFMkhMQkpXTTZDWlhXTDZCVFZTMkhYTlA2WkM3SEIzWUNZRUVDVkpSWUlWQkEiLCJpYXQiOjE2OTMyNjA0MjIsIm5hdHMiOnsidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyLCJpc3N1ZXJfYWNjb3VudCI6IkFETlUyUVJYQkQ0WktQSkJYMlc0R1BZSVpQSk5VMjVJVkM2N1RQQVJFMjI3NTVLTE40SlNKUlFIIn19.Qs4u3ehBkO96ZmvPGltbC8vYZxpu57-Oa8FeP9bDsk0HtY0Jghu50ZDkvl3iL5dN471X5eT9uz0dJHc1cBS_Bg"
        }
    },
    "logging_preset": "production",
    "nats_config": {
        "server_name": "leaf-01",
        "port": 4224,
        "host": "127.0.0.1",
        "jetstream": {
            "domain": "leaf-01",
            "max_memory_store": 1073741824,
            "max_file_store": 1073741824
        },
        "websocket": {
            "host": "0.0.0.0",
            "port": 10445
        },
        "mqtt": {
            "host": "0.0.0.0",
            "port": 8885
        },
        "leafnodes": {
            "remotes": [
                {
                    "url": "nats-leaf://server-01.example.com:7222",
                    "account": "ADNU2QRXBD4ZKPJBX2W4GPYIZPJNU25IVC67TPARE22755KLN4JSJRQH"
                }
            ]
        },
        "operator": "eyJhbGciOiJlZDI1NTE5LW5rZXkiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoidGVzdC1vcGVyYXRvciIsInN1YiI6Ik9ETzNJVkQzWkdEWEFFSERET1RET0tVVk40WkM1UVlFU1RONUkyUEFMVk9JTzNDTURFUVdQQVhTIiwiaXNzIjoiT0RPM0lWRDNaR0RYQUVIRERPVERPS1VWTjRaQzVRWUVTVE41STJQQUxWT0lPM0NNREVRV1BBWFMiLCJqdGkiOiJHWE5NU1RYWVlXWTRaVzZCNFYyTUNaMklFSk9KVUhJRTVVUUdaVTIzSTVCTUtGSUFWUUZBIiwiaWF0IjoxNjkzMjYwNDIyLCJuYXRzIjp7InR5cGUiOiJvcGVyYXRvciIsInZlcnNpb24iOjJ9fQ.aadO53UH-iWOBYlC0FdD-8OuO7fG-srsf5Re-_dwqx9BaM3Ps-Y2st_RzBWnMpXgvq-e4GXzRRx1M23pr9HtCA",
        "system_account": "ADNU2QRXBD4ZKPJBX2W4GPYIZPJNU25IVC67TPARE22755KLN4JSJRQH",
        "resolver": {
            "type": "full",
            "dir": "./nats-01/jwt",
            "allow_delete": true,
            "interval": "2m"
        },
        "resolver_preload": {
            "ADNU2QRXBD4ZKPJBX2W4GPYIZPJNU25IVC67TPARE22755KLN4JSJRQH": "eyJhbGciOiJlZDI1NTE5LW5rZXkiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiU1lTIiwic3ViIjoiQUROVTJRUlhCRDRaS1BKQlgyVzRHUFlJWlBKTlUyNUlWQzY3VFBBUkUyMjc1NUtMTjRKU0pSUUgiLCJpc3MiOiJPRE8zSVZEM1pHRFhBRUhERE9URE9LVVZONFpDNVFZRVNUTjVJMlBBTFZPSU8zQ01ERVFXUEFYUyIsImp0aSI6IkdYTk1TVFc1WU5OUEhSRlRXQkM1RU9SQUNNUklQQlk1R0I0VlNUNVFBVTdETDQyVTJVRlEiLCJpYXQiOjE2OTMyNjA0MjIsIm5hdHMiOnsidHlwZSI6ImFjY291bnQiLCJ2ZXJzaW9uIjoyLCJzaWduaW5nX2tleXMiOlt7ImtleSI6IkFDRk9XVTZXQU1UV0NHNzJXWTVYN0pWRFU3WExKU0cyWENQTUZISFQ2M1BIR1RWRzVKVDI1VlVDIiwicm9sZSI6Im1vbml0b3IiLCJ0ZW1wbGF0ZSI6eyJwdWIiOnsiYWxsb3ciOlsiJFNZUy5SRVEuQUNDT1VOVC4qLioiLCIkU1lTLlJFUS5TRVJWRVIuKi4qIl19LCJzdWIiOnsiYWxsb3ciOlsiJFNZUy5BQ0NPVU5ULiouPiIsIiRTWVMuU0VSVkVSLiouPiJdfSwic3VicyI6MTAwLCJwYXlsb2FkIjoxMDQ4NTc2LCJhbGxvd2VkX2Nvbm5lY3Rpb25fdHlwZXMiOlsiU1RBTkRBUkQiLCJXRUJTT0NLRVQiXX0sImtpbmQiOiJ1c2VyX3Njb3BlIn0seyJrZXkiOiJBQlVIM0gzQ0VTRkFXU1NVNE1PTlhOVllKNVpLQ0ZWWlNYM0RHNFNDUEY3RUhFTVBETVE1TVYyNiIsInJvbGUiOiJpc3N1ZXIiLCJ0ZW1wbGF0ZSI6eyJwdWIiOnsiYWxsb3ciOlsiJFNZUy5SRVEuQ0xBSU1TLiouIiwiJFNZUy5SRVEuQUNDT1VOVC4qLkNMQUlNUy4qIl19LCJzdWJzIjoxMCwicGF5bG9hZCI6MTA0ODU3NiwiYWxsb3dlZF9jb25uZWN0aW9uX3R5cGVzIjpbIlNUQU5EQVJEIiwiV0VCU09DS0VUIl19LCJraW5kIjoidXNlcl9zY29wZSJ9LHsia2V5IjoiQURER0FYSDNFRlpQM1NaSlVQQUJCR0tYT1lBT1NTWEpHNVc0VlNaNUxTUTQ2U0ZNRElDNUJJQzMiLCJyb2xlIjoiYWRtaW5pc3RyYXRvciIsInRlbXBsYXRlIjp7InB1YiI6eyJhbGxvdyI6WyI-Il19LCJzdWIiOnsiYWxsb3ciOlsiPiJdfSwic3VicyI6MTAsInBheWxvYWQiOjEwNDg1NzYsImFsbG93ZWRfY29ubmVjdGlvbl90eXBlcyI6WyJTVEFOREFSRCIsIldFQlNPQ0tFVCJdfSwia2luZCI6InVzZXJfc2NvcGUifSx7ImtleSI6IkFCUUM0QkNCR1lKRVlHVzVETFJGVTNZVVI3WVpDU09YNk9FVkcyNlNBTkZQQVZVWUhBVDRUSEdUIiwicm9sZSI6ImxlYWZub2RlIiwidGVtcGxhdGUiOnsicHViIjp7ImFsbG93IjpbIj4iXX0sInN1YiI6eyJhbGxvdyI6WyI-Il19LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOjEwNDg1NzYsImFsbG93ZWRfY29ubmVjdGlvbl90eXBlcyI6WyJMRUFGTk9ERSIsIkxFQUZOT0RFX1dTIl19LCJraW5kIjoidXNlcl9zY29wZSJ9XSwiZXhwb3J0cyI6W3siZGVzY3JpcHRpb24iOiJBY2NvdW50IHNwZWNpZmljIG1vbml0b3Jpbmcgc3RyZWFtIiwiaW5mb191cmwiOiJodHRwczovL2RvY3MubmF0cy5pby9uYXRzLXNlcnZlci9jb25maWd1cmF0aW9uL3N5c19hY2NvdW50cyIsIm5hbWUiOiJhY2NvdW50LW1vbml0b3Jpbmctc3RyZWFtcyIsInN1YmplY3QiOiIkU1lTLkFDQ09VTlQuKi4-IiwidHlwZSI6InN0cmVhbSIsImFjY291bnRfdG9rZW5fcG9zaXRpb24iOjN9LHsiZGVzY3JpcHRpb24iOiJSZXF1ZXN0IGFjY291bnQgc3BlY2lmaWMgbW9uaXRvcmluZyBzZXJ2aWNlcyBmb3I6IFNVQlNaLCBDT05OWiwgTEVBRlosIEpTWiBhbmQgSU5GTyIsImluZm9fdXJsIjoiaHR0cHM6Ly9kb2NzLm5hdHMuaW8vbmF0cy1zZXJ2ZXIvY29uZmlndXJhdGlvbi9zeXNfYWNjb3VudHMiLCJuYW1lIjoiYWNjb3VudC1tb25pdG9yaW5nLXNlcnZpY2VzIiwic3ViamVjdCI6IiRTWVMuUkVRLkFDQ09VTlQuKi4qIiwidHlwZSI6InNlcnZpY2UiLCJyZXNwb25zZV90eXBlIjoiU3RyZWFtIiwiYWNjb3VudF90b2tlbl9wb3NpdGlvbiI6NH0seyJkZXNjcmlwdGlvbiI6IlJlcXVlc3QgYWNjb3VudCBKV1QiLCJpbmZvX3VybCI6Imh0dHBzOi8vZG9jcy5uYXRzLmlvL25hdHMtc2VydmVyL2NvbmZpZ3VyYXRpb24vc3lzX2FjY291bnRzIiwibmFtZSI6ImFjY291bnQtbG9va3VwLXNlcnZpY2UiLCJzdWJqZWN0IjoiJFNZUy5SRVEuQUNDT1VOVC4qLkNMQUlNUy5MT09LVVAiLCJ0eXBlIjoic2VydmljZSIsInJlc3BvbnNlX3R5cGUiOiJTdHJlYW0iLCJhY2NvdW50X3Rva2VuX3Bvc2l0aW9uIjo0fSx7ImRlc2NyaXB0aW9uIjoiUmVxdWVzdCBhbGwgc2VydmVycyBoZWFsdGgiLCJpbmZvX3VybCI6Imh0dHBzOi8vZG9jcy5uYXRzLmlvL25hdHMtc2VydmVyL2NvbmZpZ3VyYXRpb24vc3lzX2FjY291bnRzIiwibmFtZSI6InNlcnZlci1oZWFsdGgtc2VydmljZSIsInN1YmplY3QiOiIkU1lTLlJFUS5TRVJWRVIuKi5IRUFMVEhaIiwidHlwZSI6InNlcnZpY2UiLCJyZXNwb25zZV90eXBlIjoiU3RyZWFtIn1dLCJsaW1pdHMiOnsiaW1wb3J0cyI6MTAsImV4cG9ydHMiOjUsIndpbGRjYXJkcyI6dHJ1ZSwiY29ubiI6MTAsImxlYWYiOjEwLCJzdWJzIjoxMDAwLCJwYXlsb2FkIjoyMDk3MTUyfX19.lKZj99iabc2ae4mDKh-l5B-nNX00Vqv2QjwQbR8epLUAhkeFE07IrbVFXxOlnviN2iul6o2o26nK3nX5ss2DBA"
        }
    }
}
```

> The `remote_users` property is used to generate credential files for leafnode remote connection. On startup, credential files are generated, and each leafnode remote within nats configuration is updated with the path to the credential file. On shutdown, all files are removed. File are configured with `0600` permission when created.

## Using a configuration file from URL

Configuration file can also be defined as a URL:

```bash
NATS_MAGIC_URL="http://localhost:9000/leaf-01.natsmagic.json" natsmagic
```

## Using a configuration file from Magic Server

Configuration file can also be obtained securely from a Magic Server. The magic configuration file is never written to disk,
only the derived NATS configuration is written to temporary file storage (so secrets such as DNS provider credentials are not persisted to a file).

In order for `natsmagic` to obtain a configuration file, it must first send a request for a given public key, receive a nonce from the server, and finally send another request with a signature for the nonce. If signature is considered valid by the Magic Server, a configuration is returned as a JSON response. If signature is invalid, or if Magic Server do not reply with expected status code, `natsmagic` will fail to start.

```bash
NATS_MAGIC_URL="http://localhost:9000" NATS_MAGIC_SERVER="SUAA7U6QLN252MI44J3RU5SE3AEEKLOW4C6XWH25DAQC7JHRNSZJB2W5PQ" natsmagic
```

> The value provided to `NATS_MAGIC_SERVER` here is a Nkey seed. It is never exhanged with remote hosts, and remain secrete to the caller and the process.
> This nkey seed is used to sign the nonce when authenticating against Magic Server. Note that in order for the request to succeed, a configuration must have been declared for the public key associated to this nkey seed BEFORE starting the `natsmagic` process.
