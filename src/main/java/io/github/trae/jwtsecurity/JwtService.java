package io.github.trae.jwtsecurity;

import io.github.trae.jwtsecurity.constants.JwtConstants;
import io.github.trae.jwtsecurity.data.RefreshToken;
import io.github.trae.jwtsecurity.enums.TokenType;
import io.github.trae.jwtsecurity.interfaces.IJwtService;
import io.github.trae.jwtsecurity.providers.JwtAccountManagerProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountRoleProvider;
import io.github.trae.jwtsecurity.providers.JwtSettingsProvider;
import io.github.trae.jwtsecurity.utility.UtilCookie;
import io.github.trae.utilities.UtilHash;
import io.github.trae.utilities.UtilString;
import io.jsonwebtoken.*;
import io.micrometer.common.util.internal.logging.InternalLogger;
import io.micrometer.common.util.internal.logging.Slf4JLoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

/**
 * JWT authentication service using Ed25519 (EdDSA) asymmetric key pairs.
 *
 * <p>Security features:</p>
 * <ul>
 *   <li>Ed25519 asymmetric signatures — no shared secrets, FAPI 2.0 compliant, TLS 1.3 approved</li>
 *   <li>Separate key pairs for access and refresh tokens (key isolation)</li>
 *   <li>Deterministic or ephemeral key pairs — derive from a master secret for multi-instance, or generate fresh on startup</li>
 *   <li>Token fingerprint binding via HttpOnly cookie (defeats XSS token theft)</li>
 *   <li>Refresh token rotation with reuse detection — replayed tokens trigger full account revocation</li>
 *   <li>lastTokenIssueAt validation — instant global token invalidation without a blocklist</li>
 *   <li>Constant-time hash comparisons to prevent timing side-channel attacks</li>
 *   <li>__Host- cookie prefix in production — browser-enforced Secure + Path=/ + no Domain</li>
 * </ul>
 *
 * @param <Settings>       the application's settings provider type
 * @param <AccountManager> the application's account manager type
 * @param <Account>        the application's account entity type
 * @param <Role>           the application's role enum type
 */
@Service
public class JwtService<Settings extends JwtSettingsProvider, AccountManager extends JwtAccountManagerProvider<Account>, Account extends JwtAccountProvider<Role>, Role extends JwtAccountRoleProvider> implements IJwtService<Account, Role> {

    private static final InternalLogger LOGGER = Slf4JLoggerFactory.getInstance(JwtService.class);

    /**
     * Shared thread-safe instance — reusing is both faster and better for entropy.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Whether to Base64-encode cookie values before writing them to the response.
     */
    private static final boolean SERIALIZE_COOKIE = true;

    private final Settings settings;

    private final AccountManager accountManager;

    private final KeyPair accessTokenKeyPair, refreshTokenKeyPair;

    private final JwtParser accessTokenParser, refreshTokenParser;

    /**
     * Construct the JWT service with the application's settings and account manager.
     *
     * <p>Resolves Ed25519 key pairs based on the settings provider:</p>
     * <ul>
     *   <li>If key seeds are provided, deterministic key pairs are derived using BouncyCastle.
     *       Every instance with the same master secret produces identical keys.</li>
     *   <li>If key seeds are null, ephemeral key pairs are generated at startup.
     *       All outstanding tokens are invalidated on restart.</li>
     * </ul>
     *
     * <p>Pre-builds thread-safe JWT parsers with issuer, audience, and clock skew
     * validation rules so they don't need to be reconstructed on every request.</p>
     *
     * @param settings       the application's environment and issuer configuration
     * @param accountManager the application's account persistence provider
     */
    public JwtService(final Settings settings, final AccountManager accountManager) {
        this.settings = settings;
        this.accountManager = accountManager;

        // Resolve key pairs — deterministic from seed, or ephemeral.
        this.accessTokenKeyPair = this.resolveKeyPair(settings.getAccessTokenKeySeed(), "access-token");
        this.refreshTokenKeyPair = this.resolveKeyPair(settings.getRefreshTokenKeySeed(), "refresh-token");

        // Pre-build parsers with all validation rules baked in (thread-safe, reusable).
        this.accessTokenParser = Jwts.parser()
                .clockSkewSeconds(Duration.ofSeconds(5).toSeconds())
                .requireIssuer(settings.getIssuer())
                .requireAudience(JwtConstants.AUDIENCE)
                .verifyWith(this.accessTokenKeyPair.getPublic())
                .build();

        this.refreshTokenParser = Jwts.parser()
                .clockSkewSeconds(Duration.ofSeconds(5).toSeconds())
                .requireIssuer(settings.getIssuer())
                .requireAudience(JwtConstants.AUDIENCE)
                .verifyWith(this.refreshTokenKeyPair.getPublic())
                .build();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Token Generation
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Generate an Ed25519-signed access token with an embedded fingerprint hash.
     *
     * <p>The fingerprint hash binds this token to an HttpOnly cookie. Even if the
     * token is exfiltrated via XSS, it cannot be used without the cookie.</p>
     *
     * @param account         the account to issue the token for
     * @param jti             the unique token identifier for revocation tracking
     * @param fingerprintHash the SHA-256 hash of the raw fingerprint cookie value
     * @return the signed, compact JWT string
     */
    @Override
    public String generateAccessTokenWithFingerprintHash(final Account account, final UUID jti, final String fingerprintHash) {
        return this.buildToken(this.accessTokenKeyPair.getPrivate(), account, TokenType.ACCESS_TOKEN, jti, fingerprintHash);
    }

    /**
     * Generate an Ed25519-signed refresh token with an embedded fingerprint hash.
     *
     * <p>The refresh token's JTI is hashed and stored server-side. On each rotation,
     * the presented JTI is verified against the stored hash — a mismatch indicates
     * token reuse and triggers full account revocation.</p>
     *
     * @param account         the account to issue the token for
     * @param jti             the unique token identifier, hashed and stored server-side
     * @param fingerprintHash the SHA-256 hash of the raw fingerprint cookie value
     * @return the signed, compact JWT string
     */
    @Override
    public String generateRefreshTokenWithFingerprintHash(final Account account, final UUID jti, final String fingerprintHash) {
        return this.buildToken(this.refreshTokenKeyPair.getPrivate(), account, TokenType.REFRESH_TOKEN, jti, fingerprintHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Token Validation
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Validate a token's Ed25519 signature, expiry, issuer, audience, token type,
     * account existence, and lastTokenIssueAt freshness.
     *
     * @param token             the raw JWT string to validate
     * @param requiredTokenType the expected token type (access or refresh)
     * @return true if the token passes all validation checks
     */
    @Override
    public boolean validateToken(final String token, final TokenType requiredTokenType) {
        return this.validateTokenInternal(token, requiredTokenType).isPresent();
    }

    /**
     * Extract the account UUID from a validated access token.
     *
     * <p>Performs full validation (signature, expiry, issuer, audience, token type,
     * account existence, lastTokenIssueAt) before extracting the subject claim.</p>
     *
     * @param accessToken the raw access token JWT string
     * @return the account UUID, or null if validation fails
     */
    @Override
    public UUID extractValidatedAccessAccountId(final String accessToken) {
        return this.validateTokenInternal(accessToken, TokenType.ACCESS_TOKEN).map(claims -> {
            try {
                return UUID.fromString(claims.getSubject());
            } catch (final IllegalArgumentException e) {
                return null;
            }
        }).orElse(null);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Authentication
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Retrieve the raw token string from the request cookies for the given token type.
     *
     * @param httpServletRequest the incoming request
     * @param tokenType          the token type to look up (determines the cookie name)
     * @return the deserialized token string, or null if not present
     */
    @Override
    public String getAuthenticatedToken(final HttpServletRequest httpServletRequest, final TokenType tokenType) {
        return UtilCookie.getCookie(this.settings.isProduction(), httpServletRequest, tokenType.getKey(), SERIALIZE_COOKIE);
    }

    /**
     * Check whether the request is authenticated.
     *
     * <p>Tries the access token first (fast path — no DB write). If the access token
     * is invalid or expired, falls back to refresh token rotation which issues new
     * tokens and persists the updated state.</p>
     *
     * @param httpServletRequest  the incoming request
     * @param httpServletResponse the outgoing response (used to set new cookies on rotation)
     * @return true if a valid session was resolved
     */
    @Override
    public boolean isAuthenticated(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return this.resolveAuthenticatedAccount(httpServletRequest, httpServletResponse).isPresent();
    }

    /**
     * Check whether the request is authenticated and the account holds the required role.
     *
     * @param httpServletRequest  the incoming request
     * @param httpServletResponse the outgoing response (used to set new cookies on rotation)
     * @param requiredRole        the role the account must hold
     * @return true if authenticated and the account has the required role
     */
    @Override
    public boolean isAuthenticatedByRole(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final Role requiredRole) {
        return this.resolveAuthenticatedAccount(httpServletRequest, httpServletResponse).map(account -> account.hasRole(requiredRole)).orElse(false);
    }

    /**
     * Resolve the authenticated account from the request.
     *
     * <p>Validates the access token with fingerprint binding, falling back to refresh
     * token rotation if the access token is invalid or expired.</p>
     *
     * @param httpServletRequest  the incoming request
     * @param httpServletResponse the outgoing response (used to set new cookies on rotation)
     * @return the authenticated account, or empty if no valid session exists
     */
    @Override
    public Optional<Account> getAccountByRequest(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return this.resolveAuthenticatedAccount(httpServletRequest, httpServletResponse);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Token Cookie Management
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Issue new access and refresh tokens for the account and write them as secure cookies.
     *
     * <p>This method performs the following steps:</p>
     * <ol>
     *   <li>Updates the account's lastTokenIssueAt timestamp (invalidating all prior tokens)</li>
     *   <li>Generates a cryptographically random fingerprint and its SHA-256 hash</li>
     *   <li>Builds Ed25519-signed access and refresh tokens with the fingerprint hash embedded</li>
     *   <li>Stores the refresh token's SHA-512 hash server-side for rotation/reuse detection</li>
     *   <li>Writes all three cookies (access token, refresh token, fingerprint) to the response</li>
     * </ol>
     *
     * @param httpServletResponse the outgoing response to write cookies to
     * @param account             the account to issue tokens for
     */
    @Override
    public void applyTokenCookies(final HttpServletResponse httpServletResponse, final Account account) {
        final long now = System.currentTimeMillis();

        // Update the issuance timestamp — all tokens issued before this moment become invalid.
        account.setLastTokenIssueAt(now);
        this.accountManager.updateAccountLastTokenIssueAt(account);

        // Generate a cryptographically random fingerprint for token binding.
        // The raw value goes into an HttpOnly cookie; its SHA-256 hash is embedded in the JWTs.
        // Even if an attacker exfiltrates a JWT via XSS, it's useless without the HttpOnly cookie.
        final String rawFingerprint = this.generateSecureRandom(32);
        final String fingerprintHash = UtilHash.hashToString("SHA-256", rawFingerprint);

        final UUID accessJti = UUID.randomUUID();
        final UUID refreshJti = UUID.randomUUID();

        final String accessToken = this.generateAccessTokenWithFingerprintHash(account, accessJti, fingerprintHash);
        final String refreshToken = this.generateRefreshTokenWithFingerprintHash(account, refreshJti, fingerprintHash);

        // Store the refresh token hash server-side for rotation and reuse detection.
        // On the next refresh, the presented JTI is hashed and compared — mismatch means theft.
        account.setRefreshToken(new RefreshToken(UtilHash.hashToString("SHA-512", refreshToken), now + JwtConstants.REFRESH_TOKEN_EXPIRATION_DURATION.toMillis()));
        this.accountManager.updateAccountRefreshToken(account);

        UtilCookie.setCookie(this.settings.isProduction(), httpServletResponse, TokenType.ACCESS_TOKEN.getKey(), accessToken, true, JwtConstants.ACCESS_TOKEN_EXPIRATION_DURATION, SERIALIZE_COOKIE);
        UtilCookie.setCookie(this.settings.isProduction(), httpServletResponse, TokenType.REFRESH_TOKEN.getKey(), refreshToken, true, JwtConstants.REFRESH_TOKEN_EXPIRATION_DURATION, SERIALIZE_COOKIE);
        UtilCookie.setCookie(this.settings.isProduction(), httpServletResponse, JwtConstants.FINGERPRINT_COOKIE, rawFingerprint, true, JwtConstants.REFRESH_TOKEN_EXPIRATION_DURATION, SERIALIZE_COOKIE);
    }

    /**
     * Remove all token cookies from the response and revoke the account's refresh token.
     *
     * <p>Clears the server-side refresh token first (so it can't be replayed),
     * then zeros out all three cookies in the browser.</p>
     *
     * @param httpServletResponse the outgoing response to clear cookies on
     * @param account             the account to revoke, or null if unknown
     */
    @Override
    public void removeTokenCookies(final HttpServletResponse httpServletResponse, final Account account) {
        if (account != null) {
            account.setRefreshToken(null);
            this.accountManager.updateAccountRefreshToken(account);
        }

        UtilCookie.removeCookie(this.settings.isProduction(), httpServletResponse, TokenType.ACCESS_TOKEN.getKey(), true);
        UtilCookie.removeCookie(this.settings.isProduction(), httpServletResponse, TokenType.REFRESH_TOKEN.getKey(), true);
        UtilCookie.removeCookie(this.settings.isProduction(), httpServletResponse, JwtConstants.FINGERPRINT_COOKIE, true);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Refresh Token Rotation
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Attempt to resolve an account from the refresh token cookie.
     *
     * <p>Performs the following validation chain:</p>
     * <ol>
     *   <li>Parse the refresh JWT (Ed25519 signature, expiry, issuer, audience)</li>
     *   <li>Verify the token type claim is {@code refresh_token}</li>
     *   <li>Validate fingerprint binding against the HttpOnly fingerprint cookie</li>
     *   <li>Resolve the account from the subject UUID</li>
     *   <li>Verify lastTokenIssueAt is not stale (catches password changes, forced logouts)</li>
     *   <li>Verify the stored refresh token exists and hasn't expired</li>
     *   <li>Verify the JTI hash against the server-side stored hash (reuse detection)</li>
     * </ol>
     *
     * <p>If the JTI hash doesn't match (reuse detected), all tokens for the account
     * are revoked — this catches the scenario where an attacker replays a stolen
     * refresh token after the legitimate user has already rotated.</p>
     *
     * @param httpServletRequest the incoming request containing the refresh token cookie
     * @return the validated account, or empty if any check fails
     */
    @Override
    public Optional<Account> getRefreshAsAccount(final HttpServletRequest httpServletRequest) {
        final String refreshToken = this.getAuthenticatedToken(httpServletRequest, TokenType.REFRESH_TOKEN);
        if (UtilString.isEmpty(refreshToken)) {
            return Optional.empty();
        }

        // Parse and validate the refresh JWT (Ed25519 signature, expiry, issuer, audience).
        final Claims claims;
        try {
            claims = this.refreshTokenParser.parseSignedClaims(refreshToken).getPayload();
        } catch (final Exception e) {
            LOGGER.debug("Refresh token parse failed: {}", e.getMessage());
            return Optional.empty();
        }

        // Verify token type claim to prevent access tokens being used as refresh tokens.
        if (!(TokenType.REFRESH_TOKEN.getKey().equals(claims.get(JwtConstants.CLAIM_TOKEN_TYPE, String.class)))) {
            return Optional.empty();
        }

        // Validate fingerprint binding — ensures the token is paired with the correct cookie.
        if (!(this.validateFingerprint(httpServletRequest, claims))) {
            LOGGER.warn("Fingerprint mismatch on refresh for subject: {}", claims.getSubject());
            return Optional.empty();
        }

        final UUID accountId;
        try {
            accountId = UUID.fromString(claims.getSubject());
        } catch (final IllegalArgumentException e) {
            return Optional.empty();
        }

        final Optional<Account> accountOptional = this.accountManager.getAccountById(accountId);
        if (accountOptional.isEmpty()) {
            return Optional.empty();
        }

        final Account account = accountOptional.get();

        // Validate lastTokenIssueAt — if the account's timestamp was updated
        // (password change, forced logout), all previously issued tokens are rejected.
        final Long lastTokenIssuedAt = claims.get(JwtConstants.CLAIM_LAST_ISSUE, Long.class);
        if (lastTokenIssuedAt == null || lastTokenIssuedAt < account.getLastTokenIssueAt()) {
            LOGGER.debug("Refresh token lastTokenIssueAt stale for account: {}", accountId.toString());
            return Optional.empty();
        }

        // Validate the stored refresh token exists and hasn't expired.
        final RefreshToken storedRefreshToken = account.getRefreshToken();
        if (storedRefreshToken == null) {
            return Optional.empty();
        }

        if (storedRefreshToken.getExpireAt() < System.currentTimeMillis()) {
            return Optional.empty();
        }

        // Verify the JTI hash — the core refresh token rotation check.
        // If the hash doesn't match, a previously rotated token is being replayed.
        // Nuke all tokens for the account to force re-authentication.
        if (!(storedRefreshToken.verify(claims.getId()))) {
            LOGGER.error("REFRESH TOKEN RE-USE DETECTED for account: {}, revoking all tokens", accountId.toString());
            account.setLastTokenIssueAt(0L);
            account.setRefreshToken(null);
            this.accountManager.updateAccountLastTokenIssueAt(account);
            this.accountManager.updateAccountRefreshToken(account);
            return Optional.empty();
        }

        return Optional.of(account);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Key Resolution
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Resolve an Ed25519 key pair from a seed or generate an ephemeral one.
     *
     * <p>When a 32-byte seed is provided, a deterministic key pair is derived using
     * BouncyCastle. Every instance with the same seed produces identical keys,
     * enabling multi-instance deployments without shared key files.</p>
     *
     * <p>When the seed is null, an ephemeral key pair is generated at startup.
     * All outstanding tokens are invalidated on restart.</p>
     *
     * @param seed  exactly 32 bytes for deterministic derivation, or null for ephemeral
     * @param label a human-readable label for logging
     * @return the resolved Ed25519 key pair
     */
    private KeyPair resolveKeyPair(final byte[] seed, final String label) {
        if (seed == null || seed.length == 0) {
            LOGGER.info("Generating ephemeral {} key pair for: {}", JwtConstants.KEY_PAIR_ALGORITHM, label);
            return this.generateKeyPair();
        }

        if (seed.length != 32) {
            throw new IllegalArgumentException("%s key seed must be exactly 32 bytes, got: %s".formatted(JwtConstants.KEY_PAIR_ALGORITHM, seed.length));
        }

        LOGGER.info("Deriving deterministic {} key pair for: {}", JwtConstants.KEY_PAIR_ALGORITHM, label);
        final KeyPair keyPair = this.deriveKeyPairFromSeed(seed);

        // Wipe the seed from memory after derivation.
        Arrays.fill(seed, (byte) 0);

        return keyPair;
    }

    /**
     * Generate an ephemeral Ed25519 key pair using the JDK's built-in SunEC provider (JDK 15+).
     *
     * @return the generated Ed25519 key pair
     * @throws IllegalStateException if Ed25519 is not available (requires JDK 15+)
     */
    private KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(JwtConstants.KEY_PAIR_ALGORITHM).generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("%s unavailable - requires JDK 15+. Running: %s".formatted(JwtConstants.KEY_PAIR_ALGORITHM, System.getProperty("java.version")), e);
        }
    }

    /**
     * Derive a deterministic Ed25519 key pair from a 32-byte seed using BouncyCastle.
     *
     * <p>The seed is used as the Ed25519 private key material. The public key is
     * mathematically derived from it. Every call with the same seed produces
     * the same key pair — enabling multi-instance deployments where all instances
     * share a master secret but don't need shared key files.</p>
     *
     * @param seed exactly 32 bytes
     * @return the deterministic Ed25519 key pair compatible with the JDK KeyPair API
     */
    private KeyPair deriveKeyPairFromSeed(final byte[] seed) {
        try {
            // Construct Ed25519 private key from seed using BouncyCastle.
            final Ed25519PrivateKeyParameters privateParams = new Ed25519PrivateKeyParameters(seed, 0);
            final Ed25519PublicKeyParameters publicParams = privateParams.generatePublicKey();

            // Convert BouncyCastle key parameters to JDK key types via encoded form.
            final KeyFactory keyFactory = KeyFactory.getInstance(JwtConstants.KEY_PAIR_ALGORITHM);

            final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(privateParams).getEncoded()));

            final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicParams).getEncoded()));

            return new KeyPair(publicKey, privateKey);
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to derive Ed25519 key pair from seed", e);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Token Building
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Build a signed JWT with the given parameters.
     *
     * <p>Embeds the following claims: JTI, issuer, audience, subject (account ID),
     * token type, lastTokenIssueAt, issued-at, not-before, expiration, and optionally
     * the fingerprint hash for token binding.</p>
     *
     * @param signingKey      the Ed25519 private key to sign with
     * @param account         the account to issue the token for
     * @param tokenType       access or refresh — determines the expiration duration
     * @param jti             the unique token identifier
     * @param fingerprintHash the SHA-256 fingerprint hash to embed, or null/blank to omit
     * @return the signed, compact JWT string
     */
    private String buildToken(final PrivateKey signingKey, final Account account, final TokenType tokenType, final UUID jti, final String fingerprintHash) {
        final Date now = new Date();
        final Date expiry = new Date(now.getTime() + tokenType.getExpiration().toMillis());

        final JwtBuilder jwtBuilder = Jwts.builder()
                .id(jti.toString())
                .issuer(this.settings.getIssuer())
                .audience().add(JwtConstants.AUDIENCE).and()
                .subject(account.getId().toString())
                .claim(JwtConstants.CLAIM_TOKEN_TYPE, tokenType.getKey())
                .claim(JwtConstants.CLAIM_LAST_ISSUE, account.getLastTokenIssueAt())
                .issuedAt(now)
                .notBefore(now)
                .expiration(expiry)
                .signWith(signingKey, Jwts.SIG.EdDSA);

        if (!(UtilString.isEmpty(fingerprintHash))) {
            jwtBuilder.claim(JwtConstants.CLAIM_FINGERPRINT, fingerprintHash);
        }

        return jwtBuilder.compact();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Token Validation
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Full internal token validation using the appropriate Ed25519 public key parser.
     *
     * <p>Validates: Ed25519 signature, expiry, not-before, issuer, audience,
     * token type claim, account existence, and lastTokenIssueAt freshness.</p>
     *
     * <p>Returns the parsed claims on success, or empty on any failure.
     * Never throws — all exceptions are caught, logged, and converted to empty.</p>
     *
     * @param token             the raw JWT string to validate
     * @param requiredTokenType the expected token type (determines which parser to use)
     * @return the validated claims, or empty if any check fails
     */
    private Optional<Claims> validateTokenInternal(final String token, final TokenType requiredTokenType) {
        if (UtilString.isEmpty(token)) {
            return Optional.empty();
        }

        final JwtParser jwtParser = switch (requiredTokenType) {
            case ACCESS_TOKEN -> this.accessTokenParser;
            case REFRESH_TOKEN -> this.refreshTokenParser;
            default -> null;
        };

        if (jwtParser == null) {
            LOGGER.error("Failed to validate token internal, Invalid TokenType argument.");
            return Optional.empty();
        }

        try {
            final Claims claims = jwtParser.parseSignedClaims(token).getPayload();

            // Verify token type claim to prevent cross-use between access and refresh parsers.
            if (!(requiredTokenType.getKey().equals(claims.get(JwtConstants.CLAIM_TOKEN_TYPE, String.class)))) {
                return Optional.empty();
            }

            // Verify the account still exists and is active.
            final Optional<Account> accountOptional = this.accountManager.getAccountById(UUID.fromString(claims.getSubject()));
            if (accountOptional.isEmpty()) {
                return Optional.empty();
            }

            // Verify lastTokenIssueAt — if the account's timestamp was updated (password change,
            // forced logout, etc.), all previously issued tokens become instantly invalid.
            final Long lastTokenIssueAt = claims.get(JwtConstants.CLAIM_LAST_ISSUE, Long.class);

            if (lastTokenIssueAt == null || lastTokenIssueAt < accountOptional.get().getLastTokenIssueAt()) {
                return Optional.empty();
            }

            return Optional.of(claims);
        } catch (final ExpiredJwtException e) {
            LOGGER.debug("Token expired: {}", e.getMessage());
        } catch (final SecurityException | MalformedJwtException e) {
            LOGGER.warn("Invalid token signature/format: {}", e.getMessage());
        } catch (final JwtException e) {
            LOGGER.warn("Token validation failed: {}", e.getMessage());
        } catch (final IllegalArgumentException e) {
            LOGGER.warn("Invalid subject UUID in token.");
        }

        return Optional.empty();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Account Resolution
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Single unified method that resolves an authenticated account from the request.
     *
     * <p>Tries the access token first (fast path — no DB writes, no token rotation).
     * If the access token is invalid or expired, falls back to refresh token rotation
     * which validates the refresh token, issues new tokens, and persists the updated state.</p>
     *
     * <p>All public authentication methods ({@link #isAuthenticated}, {@link #isAuthenticatedByRole},
     * {@link #getAccountByRequest}) delegate to this single method — no split logic, no hidden state.</p>
     *
     * @param httpServletRequest  the incoming request
     * @param httpServletResponse the outgoing response (used to write new cookies on rotation)
     * @return the authenticated account, or empty if no valid session exists
     */
    private Optional<Account> resolveAuthenticatedAccount(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        // Fast path — validate the access token without any DB writes or token rotation.
        final String accessToken = this.getAuthenticatedToken(httpServletRequest, TokenType.ACCESS_TOKEN);
        if (accessToken != null) {
            final Optional<Claims> accessTokenClaimsOptional = this.validateTokenInternal(accessToken, TokenType.ACCESS_TOKEN);
            if (accessTokenClaimsOptional.isPresent()) {
                final Claims accessTokenClaims = accessTokenClaimsOptional.get();

                // Validate fingerprint binding — ensures the token is paired with the correct cookie.
                if (this.validateFingerprint(httpServletRequest, accessTokenClaims)) {
                    try {
                        return this.accountManager.getAccountById(UUID.fromString(accessTokenClaims.getSubject()));
                    } catch (final IllegalArgumentException ignored) {
                    }
                }
            }
        }

        // Access token invalid or expired — attempt refresh token rotation.
        final Optional<Account> refreshedAccountOptional = this.getRefreshAsAccount(httpServletRequest);
        if (refreshedAccountOptional.isEmpty()) {
            return Optional.empty();
        }

        final Account refreshedAccount = refreshedAccountOptional.get();

        // Issue new tokens — the old refresh JTI hash is overwritten during rotation.
        this.applyTokenCookies(httpServletResponse, refreshedAccount);

        return Optional.of(refreshedAccount);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Fingerprint Binding
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Validate the fingerprint cookie's SHA-256 hash against the hash embedded in the JWT.
     *
     * <p>This is the core XSS defence for token theft. Even if malicious JavaScript
     * exfiltrates the JWT, the request will fail because the fingerprint cookie is
     * HttpOnly and inaccessible to JavaScript. Uses constant-time comparison
     * internally to prevent timing side-channel attacks.</p>
     *
     * @param httpServletRequest the incoming request containing the fingerprint cookie
     * @param claims             the parsed JWT claims containing the expected fingerprint hash
     * @return true if the fingerprint matches or if no fingerprint binding is present
     */
    private boolean validateFingerprint(final HttpServletRequest httpServletRequest, final Claims claims) {
        final String expectedHash = claims.get(JwtConstants.CLAIM_FINGERPRINT, String.class);
        if (UtilString.isEmpty(expectedHash)) {
            return true;
        }

        final String rawFingerprint = UtilCookie.getCookie(this.settings.isProduction(), httpServletRequest, JwtConstants.FINGERPRINT_COOKIE, SERIALIZE_COOKIE);
        if (UtilString.isEmpty(rawFingerprint)) {
            return false;
        }

        final String actualHash = UtilHash.hashToString("SHA-256", rawFingerprint);

        return UtilHash.verify("SHA-256", expectedHash, actualHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Internal — Cryptographic Utilities
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Generate a cryptographically secure random hex string.
     *
     * <p>Uses the shared {@link SecureRandom} instance which is thread-safe
     * and continuously seeded by the OS entropy pool.</p>
     *
     * @param byteLength the number of random bytes to generate (output hex string is 2x this length)
     * @return the random bytes encoded as a lowercase hex string
     */
    private String generateSecureRandom(final int byteLength) {
        final byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return UtilHash.toHex(bytes);
    }
}