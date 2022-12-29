These are self-signed certificates for an, arbitrary, localhost domain.  There
need to be _some_ certificate response to send the client attestation along
with, so these certs, at least for the moment, aren't verified at all and could
easily be generated on the fly.

```
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -sha256 -days 365 -subj '/CN=localhost'
```
