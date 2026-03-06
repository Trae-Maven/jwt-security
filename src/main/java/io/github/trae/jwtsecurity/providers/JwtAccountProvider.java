package io.github.trae.jwtsecurity.providers;

import io.github.trae.jwtsecurity.data.RefreshToken;

import java.util.UUID;

public interface JwtAccountProvider<Role extends Enum<?>> {

    UUID getId();

    boolean hasRole(final Role role);

    long getLastTokenIssueAt();

    void setLastTokenIssueAt(final long lastTokenIssueAt);

    RefreshToken getRefreshToken();

    void setRefreshToken(final RefreshToken refreshToken);
}