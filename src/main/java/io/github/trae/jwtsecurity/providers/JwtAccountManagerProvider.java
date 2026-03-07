package io.github.trae.jwtsecurity.providers;

import java.util.Optional;
import java.util.UUID;

/**
 * Provider interface for account persistence operations required by the JWT security framework.
 * The consuming application must implement this and register it as a Spring bean.
 *
 * <p>Example implementation:</p>
 * <pre>
 * &#64;AllArgsConstructor
 * &#64;Service
 * public class AccountManager implements JwtAccountManagerProvider&lt;Account&gt; {
 *
 *     private final AccountRepository accountRepository;
 *
 *     &#64;Override
 *     public Optional&lt;Account&gt; getAccountById(final UUID id) {
 *         return this.accountRepository.findById(id);
 *     }
 *
 *     &#64;Override
 *     public void updateAccountLastTokenIssueAt(final Account account) {
 *         this.accountRepository.updateLastTokenIssueAt(account.getId(), account.getLastTokenIssueAt());
 *     }
 *
 *     &#64;Override
 *     public void updateAccountRefreshToken(final Account account) {
 *         this.accountRepository.updateRefreshToken(account.getId(), account.getRefreshToken());
 *     }
 * }
 * </pre>
 *
 * @param <Account> the concrete account type
 */
public interface JwtAccountManagerProvider<Account extends JwtAccountProvider<?>> {

    /**
     * Retrieve an account by its unique identifier.
     *
     * @param id the account UUID
     * @return the account, or empty if not found
     */
    Optional<Account> getAccountById(final UUID id);

    /**
     * Persist the account's updated {@code lastTokenIssueAt} timestamp.
     * Called when new tokens are issued or when all tokens are revoked.
     *
     * @param account the account to update
     */
    void updateAccountLastTokenIssueAt(final Account account);

    /**
     * Persist the account's updated refresh token hash and expiry.
     * Called on token issuance, rotation, and revocation.
     *
     * @param account the account to update
     */
    void updateAccountRefreshToken(final Account account);
}