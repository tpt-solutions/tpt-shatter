# TLS test fixtures

**TEST ONLY.** These ECDSA P-256 keys and certificates exist only to exercise the
gateway's TLS code in tests. They are not secret and must never be used in a deployment.
The CA key signs only these test certificates. Regenerate with `openssl ecparam`
and `openssl x509 -req` if they ever need replacing.
