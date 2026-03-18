package io.github.trae.jwtsecurity.enums;

import io.github.trae.jwtsecurity.providers.JwtSettingsProvider;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Duration;
import java.util.function.Function;

/**
 * Defines the two token types used in the JWT authentication flow.
 *
 * <p>Each token type has a cookie/claim key and a function that resolves its
 * expiration duration from the application's {@link JwtSettingsProvider}.
 * This allows token lifetimes to be configured externally rather than
 * hardcoded in the library.</p>
 *
 * <ul>
 *   <li>{@link #ACCESS_TOKEN} — Short-lived, validated statelessly on every request.</li>
 *   <li>{@link #REFRESH_TOKEN} — Long-lived, single-use, rotated on each renewal.</li>
 * </ul>
 */
@AllArgsConstructor
@Getter
public enum TokenType {

    /**
     * Short-lived token used for authenticating API requests.
     * Resolved via {@link JwtSettingsProvider#getAccessTokenExpiration()}.
     */
    ACCESS_TOKEN("accessToken", JwtSettingsProvider::getAccessTokenExpiration),

    /**
     * Long-lived token used to silently re-issue access tokens.
     * Resolved via {@link JwtSettingsProvider#getRefreshTokenExpiration()}.
     */
    REFRESH_TOKEN("refreshToken", JwtSettingsProvider::getRefreshTokenExpiration);

    /**
     * The key used for cookie names and JWT claim identification.
     */
    private final String key;

    /**
     * Function that extracts the expiration duration from the application's settings provider.
     */
    private final Function<JwtSettingsProvider, Duration> expirationFunction;
}