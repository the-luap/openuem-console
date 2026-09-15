# Apple public trust certificates

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

## Offline push certificate validation

The push import verifier uses the existing Apple Root CA plus the two roots
below. It uses the other certificates only as intermediates. These public DER
files were retrieved over HTTPS from Apple's PKI repository on 2026-09-08.
They are not installed in the OS and do not change APNs server trust or device
enrollment trust. Vendor envelope verification still uses its separate original
Apple root and explicit vendor leaf pins.

| File | Role | Not after (UTC) | SHA-256 |
| --- | --- | --- | --- |
| [AppleRootCA-G2.cer](https://www.apple.com/certificateauthority/AppleRootCA-G2.cer) | Root | Apr 30 18:10:09 2039 GMT | `c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050` |
| [AppleRootCA-G3.cer](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer) | Root | Apr 30 18:19:06 2039 GMT | `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179` |
| [AppleAAI2CA.cer](https://www.apple.com/certificateauthority/AppleAAI2CA.cer) | Intermediate | May 24 17:43:37 2028 GMT | `d3496f4b73cd67aab9f2fcb1d5aa41f8dc457769c455c792b70ddb19e92023d6` |
| [AppleAAICAG3.cer](https://www.apple.com/certificateauthority/AppleAAICAG3.cer) | Intermediate | May  6 23:46:30 2029 GMT | `a64b099dbd73ebb036b4204e1675e8aa821637d09b84980899104ad59d664a3b` |
| [AppleApplicationIntegrationCA5G1.cer](https://www.apple.com/certificateauthority/AppleApplicationIntegrationCA5G1.cer) | Intermediate | Mar 22 00:00:00 2034 GMT | `c0d8efbea821079d1b8a98e1198bfcc669331fa7a9c14f09b969f0af08ce4a43` |
| [AppleApplicationIntegrationCA7G1.cer](https://www.apple.com/certificateauthority/AppleApplicationIntegrationCA7G1.cer) | Intermediate | Mar  3 00:00:00 2038 GMT | `928265664dcb4f3e2ec82d93598f0782615e541d975e2254a27d0aa98724502e` |
| [AppleWWDRCAG4.cer](https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer) | Intermediate | Dec 10 00:00:00 2030 GMT | `ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c` |

Fingerprints and the intermediate issuer chains are tested against the retrieval
date. Runtime validation uses the current time and fails for an expired chain.
The bundle does not claim every certificate ever issued by Apple remains usable.
See [push validation](../../../../docs/apple-push-certificate-validation.md) for
input rules, certificate usage checks, update behavior and remaining acceptance.
