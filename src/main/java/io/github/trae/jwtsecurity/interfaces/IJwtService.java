package io.github.trae.jwtsecurity.interfaces;

import io.github.trae.jwtsecurity.providers.JwtAccountProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountRoleProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;
import java.util.UUID;

public interface IJwtService {

    String generateAccessToken(final JwtAccountProvider<?> account, final UUID jti);

    String generateRefreshToken(final JwtAccountProvider<?> account, final UUID jti);

    boolean isAuthenticated(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse);

    boolean isAuthenticatedByRole(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final JwtAccountRoleProvider requiredRole);

    Optional<JwtAccountProvider<?>> getAccountByRequest(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse);

    void applyTokenCookies(final HttpServletResponse httpServletResponse, final JwtAccountProvider<?> account);

    void removeTokenCookies(final HttpServletResponse httpServletResponse, final JwtAccountProvider<?> account);
}