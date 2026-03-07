package io.github.trae.jwtsecurity.providers;

/**
 * Provider interface for environment and application settings required by the JWT security framework.
 * The consuming application must implement this and register it as a Spring bean.
 *
 * <p>Example implementation:</p>
 * <pre>
 * &#64;Service
 * public class MyJwtSettings implements JwtSettingsProvider {
 *
 *     &#64;Override
 *     public boolean isProduction() { return true; }
 *
 *     &#64;Override
 *     public String getIssuer() { return "myapp.com"; }
 *
 *     &#64;Override
 *     public byte[] getAccessTokenKeySeed() {
 *         return null;
 *     }
 *
 *     &#64;Override
 *     public byte[] getRefreshTokenKeySeed() {
 *         return null;
 *     }
 * }
 * </pre>
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