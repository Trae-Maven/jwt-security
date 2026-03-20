package io.github.trae.jwtsecurity.data;

import io.github.trae.jwtsecurity.data.interfaces.IRefreshToken;
import io.github.trae.utilities.UtilHash;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Server-side representation of a refresh token.
 * Stores the SHA-512 hash of the token's JTI, its expiration timestamp,
 * and the timestamp of the last rotation for concurrent request grace handling.
 *
 * <p>The {@code rotatedAt} field records when this refresh token hash was last written.
 * During refresh rotation, concurrent requests may arrive with the previous JTI before
 * the browser has received and stored the new cookies. If a JTI mismatch occurs within
 * a short grace window of {@code rotatedAt}, it is treated as a benign race condition
 * rather than a token reuse attack — the request is silently rejected without revoking
 * the session. Genuine reuse attacks will present stale JTIs well outside this window.</p>
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RefreshToken implements IRefreshToken {

    private String tokenHash;
    private long expireAt;

    /**
     * Epoch millis when this refresh token hash was last written (i.e., when rotation occurred).
     * Used to distinguish concurrent rotation races from genuine token reuse attacks.
     */
    private long rotatedAt;

    /**
     * Construct a refresh token without an explicit rotatedAt timestamp.
     * Defaults rotatedAt to the current time.
     *
     * @param tokenHash the SHA-512 hash of the refresh token's JTI
     * @param expireAt  the expiration timestamp in epoch millis
     */
    public RefreshToken(final String tokenHash, final long expireAt) {
        this(tokenHash, expireAt, System.currentTimeMillis());
    }

    /**
     * Verify a presented token JTI against the stored hash.
     * Uses constant-time comparison internally to prevent timing side-channel attacks.
     *
     * @param token the raw JTI string to verify
     * @return true if the hash matches
     */
    @Override
    public boolean verify(final String token) {
        return UtilHash.verify("SHA-512", token, this.getTokenHash());
    }
}