package io.github.trae.jwtsecurity;

import io.github.trae.jwtsecurity.interfaces.IJwtService;
import io.github.trae.jwtsecurity.providers.JwtAccountManagerProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountProvider;
import io.github.trae.jwtsecurity.providers.JwtAccountRoleProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtService implements IJwtService {

    private final JwtAccountManagerProvider<?> accountManager;

    private final SecretKey accessTokenSecretKey, refreshTokenSecretKey;

    public JwtService(final JwtAccountManagerProvider<?> accountManager) {
        this.accountManager = accountManager;

        this.accessTokenSecretKey = null; // TODO
        this.refreshTokenSecretKey = null; // TODO
    }

    @Override
    public String generateAccessToken(final JwtAccountProvider<?> account, final UUID jti) {
        return "";
    }

    @Override
    public String generateRefreshToken(final JwtAccountProvider<?> account, final UUID jti) {
        return "";
    }

    @Override
    public boolean isAuthenticated(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return false;
    }

    @Override
    public boolean isAuthenticatedByRole(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final JwtAccountRoleProvider requiredRole) {
        return false;
    }

    @Override
    public Optional<JwtAccountProvider<?>> getAccountByRequest(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) {
        return Optional.empty();
    }

    @Override
    public void applyTokenCookies(final HttpServletResponse httpServletResponse, final JwtAccountProvider<?> account) {
    }

    @Override
    public void removeTokenCookies(final HttpServletResponse httpServletResponse, final JwtAccountProvider<?> account) {
    }
}