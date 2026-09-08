# Apple public trust anchor

`AppleIncRootCertificate.cer` is Apple's public DER root certificate, downloaded
from https://www.apple.com/appleca/AppleIncRootCertificate.cer and listed at
https://www.apple.com/certificateauthority/.

SHA-256: `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`.
Downloaded 2026-09-07. Subject: Apple Root CA; valid through 2035-02-09.

The GDMF software catalog can present a chain rooted in Apple Root CA, which is
not included in some Linux system trust stores. The catalog HTTP client adds this certificate to its scoped trust pool.
The vendor portal request verifier separately uses this root, together with
explicit operator-approved vendor certificate fingerprints, to validate the
complete chain carried in a signed portal request. It does not use OS roots.
Device enrollment and APNs keep their separate authentication/trust configuration. TLS hostname, chain and validity
verification remain enabled.
