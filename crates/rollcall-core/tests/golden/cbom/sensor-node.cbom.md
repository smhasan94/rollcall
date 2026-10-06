# Cryptographic inventory: sensor-node 1.0.0

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0.

8 cryptographic assets, 9 evidence entries.

| Asset | Type | Details | In | Evidence | Confidence | Reason |
| ----- | ---- | ------- | -- | -------- | ---------- | ------ |
| ChaCha20-Poly1305 | algorithm | ae · 256 · encrypt,decrypt,tag · 256-bit · NIST 5 | sensor-boot / chacha20poly1305@0.10.1 | Cargo.toml chacha20poly1305\[default\] | high | the crate is a dependency with its default features |
| AES-128-GCM | algorithm | ae · 128 · gcm · software-plain-ram · armv7-m · encrypt,decrypt,tag · 128-bit · NIST 1 · OID 2.16.840.1.101.3.4.1.6 | sensor-app / mbedtls@3.6.0 | build/zephyr/zephyr.elf mbedtls\_gcm\_setkey | high | the GCM key schedule is linked into the image |
| AES-128-GCM | algorithm | ae · 128 · gcm · software-plain-ram · armv7-m · encrypt,decrypt,tag · 128-bit · NIST 1 · OID 2.16.840.1.101.3.4.1.6 | sensor-app / mbedtls@3.6.0 | build/zephyr/.config:812 CONFIG\_MBEDTLS\_CIPHER\_MODE\_GCM | high | CONFIG\_MBEDTLS\_CIPHER\_MODE\_GCM=y builds GCM into mbedtls |
| ECDSA-P256 | algorithm | signature · secp256r1 · curve secp256r1 · sign,verify · 128-bit · NIST 0 | sensor-app / mbedtls@3.6.0 | build/zephyr/.config:798 CONFIG\_MBEDTLS\_ECP\_DP\_SECP256R1\_ENABLED | medium | the secp256r1 curve is enabled in Kconfig for ECDSA |
| RSA-2048 | algorithm | signature · 2048 · padding pkcs1v15 · sign,verify · 112-bit · NIST 0 | sensor-app / mbedtls@3.6.0 | build/zephyr/.config:790 CONFIG\_MBEDTLS\_RSA\_C | low | RSA is enabled in Kconfig; no call site was checked |
| SHA-256 | algorithm | hash · 256 · digest · NIST 2 · OID 2.16.840.1.101.3.4.2.1 | sensor-app / mbedtls@3.6.0 | modules/crypto/mbedtls/library/sha256.c:1 | medium | the mbedtls SHA-256 implementation is in the source tree |
| TLS | protocol | tls · 1.2 | sensor-app | build/zephyr/.config:845 CONFIG\_MBEDTLS\_SSL\_PROTO\_TLS1\_2 | low | TLS 1.2 is enabled; the version negotiated at run time is not checked |
| device-cert | certificate | X.509 · CN=sensor-node-0001 · issued by CN=Example Devices CA · valid 2026-01-01T00:00:00Z to 2036-01-01T00:00:00Z | sensor-app | src/certs/device\_cert.c:12 | medium | a PEM certificate is embedded as a string constant |
| psk | related-crypto-material | secret-key · 256-bit · active · id tls-psk | sensor-app | build/zephyr/.config:860 CONFIG\_MBEDTLS\_KEY\_EXCHANGE\_PSK\_ENABLED | medium | PSK key exchange is enabled; the key itself is provisioned at run time |
