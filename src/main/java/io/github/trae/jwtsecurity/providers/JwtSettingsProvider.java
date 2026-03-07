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
 *     public boolean isPersistentKeys() { return true; }
 *
 *     &#64;Override
 *     public String getAccessTokenKeyPath() { return "/opt/myapp/keys/access-token.key"; }
 *
 *     &#64;Override
 *     public String getRefreshTokenKeyPath() { return "/opt/myapp/keys/refresh-token.key"; }
 * }
 * </pre>
 *
 * <p>When persistent keys are enabled, the following files are created on first startup:</p>
 * <pre>
 * /opt/myapp/keys/access-token.key       (private key, PKCS#8 DER)
 * /opt/myapp/keys/access-token.key.pub   (public key, X.509 DER)
 * /opt/myapp/keys/refresh-token.key      (private key, PKCS#8 DER)
 * /opt/myapp/keys/refresh-token.key.pub  (public key, X.509 DER)
 * </pre>
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
     * Whether to persist Ed25519 key pairs to disk.
     *
     * <p>When {@code true}, key pairs are loaded from the paths returned by
     * {@link #getAccessTokenKeyPath()} and {@link #getRefreshTokenKeyPath()}.
     * If the files don't exist, new key pairs are generated and saved.</p>
     *
     * <p>When {@code false}, ephemeral key pairs are generated at startup
     * and all outstanding tokens are invalidated on restart.</p>
     *
     * @return true to persist keys across restarts
     */
    boolean isPersistentKeys();

    /**
     * File path for the access token Ed25519 key pair.
     * Only used when {@link #isPersistentKeys()} is {@code true}.
     *
     * @return the path, e.g. {@code "/opt/myapp/keys/access-token.key"}
     */
    String getAccessTokenKeyPath();

    /**
     * File path for the refresh token Ed25519 key pair.
     * Only used when {@link #isPersistentKeys()} is {@code true}.
     *
     * @return the path, e.g. {@code "/opt/myapp/keys/refresh-token.key"}
     */
    String getRefreshTokenKeyPath();
}