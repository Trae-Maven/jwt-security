package io.github.trae.jwtsecurity.providers;

import io.github.trae.jwtsecurity.data.RefreshToken;

import java.util.UUID;

/**
 * Provider interface representing an authenticated account within the JWT security framework.
 * The consuming application's account entity must implement this interface.
 *
 * <p>Example implementation:</p>
 * <pre>
 * &#64;AllArgsConstructor
 * &#64;Getter
 * &#64;Setter
 * public class Account implements JwtAccountProvider&lt;Role&gt; {
 *
 *     private UUID id;
 *     private Role role;
 *     private long lastTokenIssueAt;
 *     private RefreshToken refreshToken;
 *
 *     &#64;Override
 *     public boolean hasRole(final Role role) { return this.getRole().ordinal() >= role.ordinal(); }
 * }
 * </pre>
 *
 * @param <Role> the role enum type, must implement {@link JwtAccountRoleProvider}
 */
public interface JwtAccountProvider<Role extends JwtAccountRoleProvider> {

    /**
     * @return the unique identifier for this account
     */
    UUID getId();

    /**
     * Check whether this account holds the specified role.
     *
     * @param role the role to check
     * @return true if the account has the role
     */
    boolean hasRole(final Role role);

    /**
     * @return the timestamp (epoch millis) when tokens were last issued for this account
     */
    long getLastTokenIssueAt();

    /**
     * Set the timestamp of the most recent token issuance.
     * Setting this to {@code 0} invalidates all outstanding tokens.
     *
     * @param lastTokenIssueAt epoch millis, or 0 to revoke all tokens
     */
    void setLastTokenIssueAt(final long lastTokenIssueAt);

    /**
     * @return the stored refresh token, or null if no active refresh token exists
     */
    RefreshToken getRefreshToken();

    /**
     * Set the refresh token for this account.
     * Pass {@code null} to revoke the refresh token.
     *
     * @param refreshToken the refresh token, or null
     */
    void setRefreshToken(final RefreshToken refreshToken);
}