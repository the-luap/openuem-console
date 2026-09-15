# Native Windows protocol fixtures

`enrollment-csr.der` is a synthetic DER PKCS#10 request with an RSA-2048 public
key and a SHA-256 signature. It provides a stable public seed for CSR fuzzing.
Its private key was generated in memory and discarded; no private key is stored
in this directory. The request grants no device identity or enrollment authority.

SHA-256: `cbd9016c6d40f84a2df43f7355fa3b8cb9d21c4ba1a1e32bfc6544cd5b1d46a5`.
