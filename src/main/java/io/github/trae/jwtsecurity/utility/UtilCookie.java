package io.github.trae.jwtsecurity.utility;

import io.github.trae.utilities.UtilBase64;
import io.github.trae.utilities.UtilString;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import java.time.Duration;
import java.util.function.Function;

/**
 * Cookie utility for reading, writing, and removing HTTP cookies
 * with production-grade security attributes.
 *
 * <p>In production mode, cookies are prefixed with {@code __Host-} which instructs
 * the browser to enforce {@code Secure}, {@code Path=/}, and no {@code Domain} attribute.</p>
 */
public class UtilCookie {

    private static final Function<String, String> SERIALIZER_FUNCTION = cookieValue -> cookieValue == null ? null : UtilBase64.encodeToString(cookieValue);
    private static final Function<String, String> DESERIALIZER_FUNCTION = encodedCookieValue -> encodedCookieValue == null ? null : UtilBase64.decodeToString(encodedCookieValue);

    /**
     * Retrieve a cookie value from the request by name.
     *
     * @param production         whether to resolve the {@code __Host-} prefixed cookie name
     * @param httpServletRequest the incoming request
     * @param cookieName         the logical cookie name (without prefix)
     * @param deserialize        whether to Base64-decode the cookie value
     * @return the cookie value, or null if not found or decoding fails
     */
    public static String getCookie(final boolean production, final HttpServletRequest httpServletRequest, final String cookieName, final boolean deserialize) {
        if (httpServletRequest.getCookies() != null && !(UtilString.isEmpty(cookieName))) {
            final String resolvedCookieName = resolveCookieName(production, cookieName);

            for (final Cookie cookie : httpServletRequest.getCookies()) {
                if (UtilString.isEmpty(cookie.getName())) {
                    continue;
                }

                if (!(cookie.getName().equals(resolvedCookieName))) {
                    continue;
                }

                try {
                    final String value = cookie.getValue();

                    return deserialize ? DESERIALIZER_FUNCTION.apply(value) : value;
                } catch (final Exception e) {
                    return null;
                }
            }
        }

        return null;
    }

    /**
     * Set a cookie on the response with configurable security attributes.
     *
     * @param production          whether to apply production security (Secure, SameSite=Strict, __Host- prefix)
     * @param httpServletResponse the outgoing response
     * @param cookieName          the logical cookie name (without prefix)
     * @param cookieValue         the raw cookie value
     * @param httpOnly            whether the cookie should be inaccessible to JavaScript
     * @param maxAge              the cookie lifetime
     * @param serialize           whether to Base64-encode the cookie value
     */
    public static void setCookie(final boolean production, final HttpServletResponse httpServletResponse, final String cookieName, final String cookieValue, final boolean httpOnly, final Duration maxAge, final boolean serialize) {
        final ResponseCookie responseCookie = ResponseCookie.from(resolveCookieName(production, cookieName), serialize ? SERIALIZER_FUNCTION.apply(cookieValue) : cookieValue)
                .httpOnly(httpOnly)
                .secure(production)
                .path("/")
                .sameSite(production ? "Strict" : "Lax")
                .maxAge(maxAge)
                .build();

        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    /**
     * Remove a cookie by setting its value to empty and its max age to zero.
     *
     * @param production          whether to resolve the {@code __Host-} prefixed cookie name
     * @param httpServletResponse the outgoing response
     * @param cookieName          the logical cookie name (without prefix)
     * @param httpOnly            whether the cookie was set as HttpOnly (must match for browser to clear it)
     */
    public static void removeCookie(final boolean production, final HttpServletResponse httpServletResponse, final String cookieName, final boolean httpOnly) {
        final ResponseCookie responseCookie = ResponseCookie.from(resolveCookieName(production, cookieName), "")
                .httpOnly(httpOnly)
                .secure(production)
                .path("/")
                .sameSite(production ? "Strict" : "Lax")
                .maxAge(Duration.ZERO)
                .build();

        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    /**
     * Resolve the actual cookie name based on the environment.
     * In production, applies the {@code __Host-} prefix for enhanced browser-enforced security.
     */
    private static String resolveCookieName(final boolean production, final String cookieName) {
        return production ? "__Host-%s".formatted(cookieName) : cookieName;
    }
}