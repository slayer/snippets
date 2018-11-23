## Disable RC4 and 3DES:
Add to your main.cf:


```
# TLS Server
smtpd_tls_exclude_ciphers = RC4, 3DES, aNULL
# TLS Client
smtp_tls_exclude_ciphers = RC4, 3DES, aNULL
```
