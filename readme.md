# Jwt Security

A lightweight and flexible JWT authentication and security library for Java.

Jwt Security provides simple utilities and helpers for generating, validating, and managing JSON Web Tokens in Java applications.

The library is designed to be lightweight, fast, and easy to integrate into existing Spring-based Java applications.

Built for modern Java (Java 21+) and designed to integrate seamlessly with existing Spring infrastructure.

---

## Features

- Ed25519 (EdDSA) asymmetric signatures — no shared secrets, FAPI 2.0 compliant, TLS 1.3 approved
- Separate key pairs for access and refresh tokens (key isolation)
- Configurable token lifetimes — set access and refresh expiration via the settings provider
- Deterministic or ephemeral key pairs — derive from a master secret for multi-instance, or generate fresh on startup
- Token fingerprint binding — defeats token theft via XSS
- Refresh token rotation with reuse detection — replayed tokens trigger full account revocation
- Concurrent rotation grace window — prevents false reuse detection from parallel browser requests
- Constant-time hash comparisons to prevent timing side-channel attacks
- lastTokenIssueAt validation — instant global token invalidation without a blocklist (security events only)
- `__Host-` cookie prefix in production — browser-enforced Secure + Path=/ + no Domain
- JWT token generation and validation
- Token parsing and claim access
- Lightweight security utilities
- Minimal dependencies
- Designed for modern Java (Java 21+)
- Easy integration into Spring applications

---

## Requirements

Jwt Security is designed for Spring-based web applications.

Your project must already include the following dependencies (these are typically already included in most Spring Boot applications):
```xml
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.36</version>
    <scope>provided</scope>
</dependency>

<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>7.0.3</version>
</dependency>

<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
    <version>7.0.3</version>
</dependency>

<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>6.0.0</version>
</dependency>

<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.83</version>
</dependency>
```

These dependencies are marked as **provided** inside Jwt Security because they are expected to already exist in your application.

---

## Built-in Dependencies

Jwt Security includes several dependencies that are automatically included when you install the library.

- [Utilities](https://github.com/Trae-Maven/utilities) – Shared helper classes and performance-focused utilities used internally by the framework.
```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.5</version>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.5</version>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.5</version>
</dependency>
```

These dependencies are automatically included when installing Jwt Security and do not need to be added manually.

---

## Installation

Add the dependency to your Maven project:
```xml
<dependency>
    <groupId>io.github.trae</groupId>
    <artifactId>jwt-security</artifactId>
    <version>0.0.2</version>
</dependency>
```

---

## Integration Guide

Jwt Security requires five classes to be set up in your application. Each provider is an interface that you implement with your own application logic, and a concrete `JwtService` subclass eliminates verbose generics at every injection site.

### 1. Define Your Role Enum

Create a role enum that implements `JwtAccountRoleProvider`:
```java
public enum Role implements JwtAccountRoleProvider {
    ADMINISTRATOR, MODERATOR, STANDARD
}
```

### 2. Implement Your Account Entity

Your account class must implement `JwtAccountProvider` with your role enum:
```java
@AllArgsConstructor
@Getter
@Setter
public class Account implements JwtAccountProvider<Role> {

    private UUID id;
    private Role role;
    private long lastTokenIssueAt;
    private RefreshToken refreshToken;

    @Override
    public boolean hasRole(final Role role) { return this.getRole().ordinal() >= role.ordinal(); }
}
```

### 3. Implement Your Account Manager

Create a service that handles account persistence:
```java
@AllArgsConstructor
@Service
public class AccountManager implements JwtAccountManagerProvider<Account> {

    private final AccountRepository accountRepository;

    @Override
    public Optional<Account> getAccountById(final UUID id) {
        return this.accountRepository.findById(id);
    }

    @Override
    public void updateAccountLastTokenIssueAt(final Account account) {
        this.accountRepository.updateLastTokenIssueAt(account.getId(), account.getLastTokenIssueAt());
    }

    @Override
    public void updateAccountRefreshToken(final Account account) {
        this.accountRepository.updateRefreshToken(account.getId(), account.getRefreshToken());
    }
}
```

### 4. Implement Your Settings

Configure the JWT service with your environment settings, token lifetimes, and key derivation strategy.

**Deterministic keys** (recommended for multi-instance deployments):
```java
@Component
public class MyJwtSettings implements JwtSettingsProvider {

    @Override
    public boolean isProduction() { return true; }

    @Override
    public Duration getAccessTokenExpiration() { return Duration.ofMinutes(5); }

    @Override
    public Duration getRefreshTokenExpiration() { return Duration.ofDays(14); }

    @Override
    public String getIssuer() { return "myapp.com"; }

    @Override
    public byte[] getAccessTokenKeySeed() {
        return KeyDerivation.derive("my-master-secret:access");
    }

    @Override
    public byte[] getRefreshTokenKeySeed() {
        return KeyDerivation.derive("my-master-secret:refresh");
    }
}
```

**Token lifetime recommendations:**

| Token | Recommended | Range | Notes |
|---|---|---|---|
| Access | 5 minutes | 1–15 min | Shorter = less exposure from stolen tokens. No server-side revocation, so lifetime is the only control. |
| Refresh | 14 days | 7–30 days | Longer = fewer forced re-logins. Rotation and reuse detection limit the risk. |

**Ephemeral keys** (tokens invalidated on every restart):
```java
@Override
public byte[] getAccessTokenKeySeed() { return null; }

@Override
public byte[] getRefreshTokenKeySeed() { return null; }
```

### 5. Create Your JwtService Subclass

Create a concrete subclass that binds all the generic types in one place. This avoids repeating `JwtService<MyJwtSettings, AccountManager, Account, Role>` at every injection site across your application:
```java
@Service
public class MyJwtService extends JwtService<MyJwtSettings, AccountManager, Account, Role> {

    public MyJwtService(final MyJwtSettings settings, final AccountManager accountManager) {
        super(settings, accountManager);
    }
}
```

This is the recommended approach. You define the generics once here, and inject `MyJwtService` everywhere else with zero generic noise.

---

## Key Derivation

Jwt Security supports two modes for Ed25519 key pair management.

### Deterministic Keys (recommended for multi-instance)

When `getAccessTokenKeySeed()` and `getRefreshTokenKeySeed()` return a 32-byte seed, deterministic Ed25519 key pairs are derived using BouncyCastle. Every application instance with the same master secret produces identical key pairs — no shared key files, no mounted volumes, no key distribution.

The seed is wiped from memory immediately after key derivation.

This is the recommended approach for production deployments with multiple instances behind a load balancer.

### Built-in KeyDerivation Utility (optional)

Jwt Security ships with a `KeyDerivation` utility class that derives a deterministic 32-byte key from a context string using HKDF with HMAC-SHA256. This produces a seed suitable for Ed25519 key pair derivation, and can be used directly with the settings provider:
```java
import io.github.trae.jwtsecurity.utility.KeyDerivation;

@Override
public byte[] getAccessTokenKeySeed() {
    return KeyDerivation.derive("my-master-secret:access");
}

@Override
public byte[] getRefreshTokenKeySeed() {
    return KeyDerivation.derive("my-master-secret:refresh");
}
```

This is entirely optional — you can use any key derivation strategy (HKDF, PBKDF2, etc.) as long as the seed methods return a consistent 32-byte array for the same input across all application instances.

### Ephemeral Keys (default)

When the seed methods return `null`, new key pairs are generated at startup using the JDK's built-in Ed25519 provider. All outstanding tokens are invalidated on every restart. This is the most secure option and suitable for applications where forced re-authentication on deploy is acceptable.

> **Note:** If you use a randomly generated string (e.g. `UUID.randomUUID().toString()`) as your secret at runtime instead of a fixed configuration value, the derived seeds will be different on every JVM restart. This effectively behaves the same as ephemeral keys — all existing access tokens and refresh tokens will be invalidated each time the application starts, since the Ed25519 key pairs will differ from the previous run.

---

## Usage

Once your `MyJwtService` is registered, inject it anywhere in your application — no generics required:
```java
@AllArgsConstructor
@Controller
public class AuthController {

    private final MyJwtService jwtService;

    @PostMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response) {
        Account account = this.authenticate(request); // your authentication logic
        this.jwtService.applyTokenCookies(request, response, account);
        return "redirect:/dashboard";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Optional<Account> account = this.jwtService.getAccountByRequest(request, response);
        this.jwtService.removeTokenCookies(response, account.orElse(null));
        return "redirect:/login";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, HttpServletResponse response, Model model) {
        Optional<Account> account = this.jwtService.getAccountByRequest(request, response);
        if (account.isEmpty()) {
            return "redirect:/login";
        }
        return "dashboard";
    }

    @GetMapping("/admin")
    public String admin(HttpServletRequest request, HttpServletResponse response) {
        if (!this.jwtService.isAuthenticatedByRole(request, response, Role.ADMINISTRATOR)) {
            return "redirect:/login";
        }
        return "admin";
    }
}
```

---

## Security Overview

| Layer | Protection |
|---|---|
| **Signature Algorithm** | Ed25519 (EdDSA) — asymmetric, deterministic, side-channel resistant |
| **Key Isolation** | Separate key pairs for access and refresh tokens |
| **Key Derivation** | HKDF from master secret → deterministic Ed25519 seeds (multi-instance safe) |
| **Token Lifetimes** | Configurable via settings provider — recommended 5min access / 14 day refresh |
| **Token Binding** | Fingerprint hash in JWT + raw value in HttpOnly cookie |
| **XSS Defence** | HttpOnly cookies — JavaScript cannot access token values |
| **CSRF Defence** | SameSite=Strict in production — browser blocks cross-origin requests |
| **Cookie Hardening** | `__Host-` prefix enforces Secure + Path=/ + no Domain |
| **Token Theft** | Fingerprint binding makes stolen JWTs unusable without the cookie |
| **Replay Prevention** | Refresh token JTI hash verified server-side on every rotation |
| **Reuse Detection** | Mismatched refresh token hash triggers full account revocation (with grace window for concurrent requests) |
| **Concurrent Safety** | Rotation grace window prevents false reuse detection from parallel browser requests |
| **Session Invalidation** | lastTokenIssueAt — updated on security events (login, password change, forced logout) to revoke all tokens instantly |
| **Timing Attacks** | Constant-time hash comparisons on all verification checks |
| **Memory Safety** | Key seeds wiped from memory immediately after derivation |
