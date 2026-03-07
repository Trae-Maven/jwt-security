package io.github.trae.jwtsecurity.providers;

/**
 * Marker interface for account role enums.
 * The consuming application's role enum must implement this interface.
 *
 * <p>Example:</p>
 * <pre>
 * public enum Role implements JwtAccountRoleProvider {
 *     ADMINISTRATOR, MODERATOR, STANDARD
 * }
 * </pre>
 */
public interface JwtAccountRoleProvider {
}