# Web Hardening Record

GUN-101-TPM does not operate a separate web server. The source repository is
hosted by GitHub and Python distributions are downloaded from PyPI; those
platforms provide the HTTP security headers for the official project and
download URLs.

## Official surfaces

- Repository: https://github.com/dialga-cmd/gun101-tpm
- Downloads: https://pypi.org/project/gun101-tpm/

## Required response protections

The official surfaces are expected to provide:

- HSTS with a long max-age and preload protection;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: deny` or an equivalent CSP `frame-ancestors 'none'`;
- a restrictive Content Security Policy where the platform supports one;
- a restrictive Permissions Policy where the platform supports one; and
- HTTPS-only delivery.

GitHub currently supplies HSTS, `X-Frame-Options: deny`,
`X-Content-Type-Options: nosniff`, and a restrictive CSP for the repository.
PyPI currently supplies HSTS, `X-Frame-Options: deny`,
`X-Content-Type-Options: nosniff`, and a restrictive Permissions Policy for
the project page.

Maintainers can verify the current platform headers with:

```bash
for url in \
  https://github.com/dialga-cmd/gun101-tpm \
  https://pypi.org/project/gun101-tpm/; do
  curl -sS -L -I "$url" | grep -Ei \
    '^(HTTP/|strict-transport-security:|content-security-policy:|x-content-type-options:|x-frame-options:|permissions-policy:)'
done
```

The repository does not claim control over GitHub or PyPI response headers;
maintainers should recheck them after a hosting-platform change.