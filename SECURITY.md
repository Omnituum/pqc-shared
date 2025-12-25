# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **GitHub Security Advisories** (Preferred): Use [GitHub's private vulnerability reporting](https://github.com/Omnituum/pqc-shared/security/advisories/new)
2. **Email**: security@omnituum.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Resolution target**: Within 30 days for critical issues

### Scope

This security policy covers:
- The `@omnituum/pqc-shared` npm package
- Cryptographic implementations (Kyber, Dilithium, X25519, etc.)
- Key derivation functions (Argon2id, PBKDF2)
- Vault encryption/decryption
- File encryption (.oqe format)

### Out of Scope

- Issues in dependencies (report to respective maintainers)
- Theoretical attacks without practical exploitation
- Social engineering

## Security Best Practices

When using this library:

1. **Keep dependencies updated** - Run `pnpm update` regularly
2. **Use Argon2id vaults** - Migrate legacy PBKDF2 vaults with `migrateEncryptedVault()`
3. **Zero sensitive memory** - Use `zeroMemory()` or `withSecureData()` for key material
4. **Constant-time comparisons** - Use `constantTimeEqual()` for secrets

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (with permission).
