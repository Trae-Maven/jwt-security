package io.github.trae.jwtsecurity.data;

import io.github.trae.jwtsecurity.data.interfaces.IRefreshToken;
import io.github.trae.utilities.UtilHash;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Server-side representation of a refresh token.
 * Stores the SHA-512 hash of the token's JTI and its expiration timestamp.
 * Used for refresh token rotation and reuse detection.
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RefreshToken implements IRefreshToken {

    private String tokenHash;
    private long expireAt;

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