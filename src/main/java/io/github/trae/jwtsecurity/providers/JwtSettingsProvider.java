package io.github.trae.jwtsecurity.providers;

import java.time.Duration;

/**
 * Provider interface for environment and application settings required by the JWT security framework.
 * The consuming application must implement this and register it as a Spring bean.
 *
 * <p>Example implementation:</p>
 * <pre>{@code
 * @Service
 * public class MyJwtSettings implements JwtSettingsProvider {
 *
 *     @Override
 *     public boolean isProduction() { return true; }
 *
 *     @Override
 *     public Duration getAccessTokenExpiration() { return Duration.ofMinutes(5); }
 *
 *     @Override
 *     public Duration getRefreshTokenExpiration() { return Duration.ofDays(14); }
 *
 *     @Override
 *     public String getIssuer() { return "myapp.com"; }
 *
 *     @Override
 *     public byte[] getAccessTokenKeySeed() { return null; }
 *
 *     @Override
 *     public byte[] getRefreshTokenKeySeed() { return null; }
 * }
 * }</pre>
 *
 * <p>When key seeds are provided, deterministic Ed25519 key pairs are derived from them
 * using BouncyCastle. Every application instance with the same master secret produces
 * identical key pairs, enabling multi-instance deployments without shared key files.</p>
 *
 * <p>When key seeds return {@code null}, ephemeral key pairs are generated at startup
 * and all outstanding tokens are invalidated on restart.</p>
 */
public interface JwtSettingsProvider {

    /**
     * Whether the application is running in production mode.
     * Controls cookie security attributes ({@code __Host-} prefix, {@code Secure}, {@code SameSite=Strict}).
     *
     * @return true if production
     */
    boolean isProduction();

    /**
     * The lifetime of access tokens. Access tokens are short-lived and validated
     * statelessly on every authenticated request.
     *
     * <p>Recommended: 5 minutes. Shorter lifetimes limit the window of abuse
     * for stolen tokens since there is no server-side revocation mechanism
     * for access tokens.</p>
     *
     * @return the access token expiration duration
     */
    Duration getAccessTokenExpiration();

    /**
     * The lifetime of refresh tokens. Refresh tokens are long-lived and used to
     * silently re-issue access tokens via rotation. Each refresh token is single-use;
     * a new refresh token is issued on every rotation.
     *
     * <p>Recommended: 7–14 days. Longer lifetimes reduce the frequency of
     * forced re-authentication at the cost of a wider revocation window.</p>
     *
     * @return the refresh token expiration duration
     */
    Duration getRefreshTokenExpiration();

    /**
     * The JWT issuer claim value. Typically the application name or domain.
     *
     * @return the issuer string
     */
    String getIssuer();

    /**
     * Optional 32-byte seed for deterministic Ed25519 access token key derivation.
     * When non-null, the key pair is derived from this seed — identical across all instances
     * sharing the same master secret.
     * When null, an ephemeral key pair is generated at startup (invalidated on restart).
     *
     * <p>Typically derived from a master secret via HKDF:</p>
     * <pre>
     * Arrays.copyOf(RootKeyEngine.derive("JWT:ACCESS_TOKEN").getBytes(), 32);
     * </pre>
     *
     * @return exactly 32 bytes for Ed25519 seed derivation, or null for ephemeral keys
     */
    byte[] getAccessTokenKeySeed();

    /**
     * Optional 32-byte seed for deterministic Ed25519 refresh token key derivation.
     * When non-null, the key pair is derived from this seed — identical across all instances
     * sharing the same master secret.
     * When null, an ephemeral key pair is generated at startup (invalidated on restart).
     *
     * <p>Typically derived from a master secret via HKDF:</p>
     * <pre>
     * Arrays.copyOf(RootKeyEngine.derive("JWT:REFRESH_TOKEN").getBytes(), 32);
     * </pre>
     *
     * @return exactly 32 bytes for Ed25519 seed derivation, or null for ephemeral keys
     */
    byte[] getRefreshTokenKeySeed();
}