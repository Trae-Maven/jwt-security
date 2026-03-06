package io.github.trae.jwtsecurity.providers;

import java.util.Optional;
import java.util.UUID;

public interface JwtAccountManagerProvider<Account extends JwtAccountProvider<?>> {

    Optional<Account> getAccountById(final UUID id);

    void updateAccountLastTokenIssueAt(final Account account);

    void updateAccountRefreshToken(final Account account);
}