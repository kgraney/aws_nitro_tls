
For logging TLS session keys for use by Wireshark.
```
SSHKEYLOGFILE=/tmp/aws_nitro_tls_client_keylog.txt
```


For local testing listening on a vsock:
```
socat TCP-LISTEN:8080,reuseaddr,fork VSOCK:1:5000
```
