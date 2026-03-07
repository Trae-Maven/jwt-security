package io.github.trae.jwtsecurity.constants;

import io.github.trae.jwtsecurity.enums.TokenType;

import java.time.Duration;

/**
 * Constants used throughout the JWT security framework.
 */
public class JwtConstants {

    public static final Duration ACCESS_TOKEN_EXPIRATION_DURATION = TokenType.ACCESS_TOKEN.getExpiration();

    public static final Duration REFRESH_TOKEN_EXPIRATION_DURATION = TokenType.REFRESH_TOKEN.getExpiration();

    /**
     * Asymmetric key pair algorithm — Ed25519 (EdDSA).
     */
    public static final String KEY_PAIR_ALGORITHM = "Ed25519";

    /**
     * Default JWT audience claim value.
     */
    public static final String AUDIENCE = "web";

    /**
     * Cookie name for the token fingerprint binding value.
     */
    public static final String FINGERPRINT_COOKIE = "fgp";

    /**
     * JWT claim key for the fingerprint hash.
     */
    public static final String CLAIM_FINGERPRINT = "fgp";

    /**
     * JWT claim key for the token type (access or refresh).
     */
    public static final String CLAIM_TOKEN_TYPE = "token_type";

    /**
     * JWT claim key for the token issuance timestamp, used for global invalidation.
     */
    public static final String CLAIM_LAST_ISSUE = "lastTokenIssueAt";
}