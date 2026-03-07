# Jwt Security

A lightweight and flexible JWT authentication and security library for Java.

Jwt Security provides simple utilities and helpers for generating, validating, and managing JSON Web Tokens in Java applications.

The library is designed to be lightweight, fast, and easy to integrate into existing Spring-based Java applications.

Built for modern Java (Java 21+) and designed to integrate seamlessly with existing Spring infrastructure.

---

## Features

- Ed25519 (EdDSA) asymmetric signatures — no shared secrets, FAPI 2.0 compliant, TLS 1.3 approved
- Separate key pairs for access and refresh tokens (key isolation)
- Persistent or ephemeral key pairs — survive restarts or invalidate all sessions on deploy
- Token fingerprint binding — defeats token theft via XSS
- Refresh token rotation with reuse detection — replayed tokens trigger full account revocation
- Constant-time hash comparisons to prevent timing side-channel attacks
- lastTokenIssueAt validation — instant global token invalidation without a blocklist
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
    <version>0.0.1</version>
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

Configure the JWT service with your environment settings:

```java
@Service
public class MyJwtSettings implements JwtSettingsProvider {

    @Override
    public boolean isProduction() { return true; }

    @Override
    public String getIssuer() { return "myapp.com"; }

    @Override
    public boolean isPersistentKeys() { return true; }

    @Override
    public String getAccessTokenKeyPath() { return "/opt/myapp/keys/access-token.key"; }

    @Override
    public String getRefreshTokenKeyPath() { return "/opt/myapp/keys/refresh-token.key"; }
}
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

## Key Persistence

Jwt Security supports two modes for Ed25519 key pair management.

### Ephemeral Keys (default)

When `isPersistentKeys()` returns `false`, new key pairs are generated at startup. All outstanding tokens are invalidated on every restart. This is the most secure option and suitable for applications where forced re-authentication on deploy is acceptable.

### Persistent Keys

When `isPersistentKeys()` returns `true`, key pairs are loaded from the file paths specified in your settings. On first startup, if the key files don't exist, they are automatically generated and saved to disk. Subsequent startups load the existing keys, preserving all active sessions across restarts.

The following files are created on first startup:

```
/opt/myapp/keys/access-token.key       (private key, PKCS#8 DER)
/opt/myapp/keys/access-token.key.pub   (public key, X.509 DER)
/opt/myapp/keys/refresh-token.key      (private key, PKCS#8 DER)
/opt/myapp/keys/refresh-token.key.pub  (public key, X.509 DER)
```

On Unix systems, private key files are automatically restricted to owner-read-only permissions.

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
        this.jwtService.applyTokenCookies(response, account);
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
| **Token Binding** | Fingerprint hash in JWT + raw value in HttpOnly cookie |
| **XSS Defence** | HttpOnly cookies — JavaScript cannot access token values |
| **CSRF Defence** | SameSite=Strict in production — browser blocks cross-origin requests |
| **Cookie Hardening** | `__Host-` prefix enforces Secure + Path=/ + no Domain |
| **Token Theft** | Fingerprint binding makes stolen JWTs unusable without the cookie |
| **Replay Prevention** | Refresh token JTI hash verified server-side on every rotation |
| **Reuse Detection** | Mismatched refresh token hash triggers full account revocation |
| **Session Invalidation** | lastTokenIssueAt — update the timestamp to revoke all tokens instantly |
| **Timing Attacks** | Constant-time hash comparisons on all verification checks |
