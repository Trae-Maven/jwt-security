package io.github.trae.jwtsecurity.interfaces;

import io.github.trae.jwtsecurity.enums.TokenType;
import io.github.trae.jwtsecurity.providers.JwtAccountProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountRoleProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;
import java.util.UUID;

public interface IJwtService<Account extends JwtAccountProvider<Role>, Role extends JwtAccountRoleProvider> {

    String generateAccessTokenWithFingerprintHash(final Account account, final UUID jti, final String fingerprintHash);

    String generateRefreshTokenWithFingerprintHash(final Account account, final UUID jti, final String fingerprintHash);

    default String generateAccessToken(final Account account, final UUID jti) {
        return this.generateAccessTokenWithFingerprintHash(account, jti, null);
    }

    default String generateRefreshToken(final Account account, final UUID jti) {
        return this.generateRefreshTokenWithFingerprintHash(account, jti, null);
    }

    boolean validateToken(final String token, final TokenType requiredTokenType);

    UUID extractValidatedAccessAccountId(final String accessToken);

    String getAuthenticatedToken(final HttpServletRequest httpServletRequest, final TokenType tokenType);

    boolean isAuthenticated(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse);

    boolean isAuthenticatedByRole(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final Role requiredRole);

    Optional<Account> getAccountByRequest(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse);

    void applyTokenCookies(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final Account account);

    void removeTokenCookies(final HttpServletResponse httpServletResponse, final Account account);

    Optional<Account> getRefreshAsAccount(final HttpServletRequest httpServletRequest);
}