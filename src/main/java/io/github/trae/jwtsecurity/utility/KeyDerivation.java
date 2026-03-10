package io.github.trae.jwtsecurity.utility;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Utility for deriving a deterministic 32-byte key from a context string using HKDF.
 *
 * <p>Uses HMAC-SHA256 with a zero-byte salt (HKDF-Extract) and a single-block
 * HKDF-Expand to produce a 32-byte output suitable for Ed25519 seed derivation.</p>
 *
 * <p>The derivation is deterministic — the same context string always produces
 * the same 32-byte key.</p>
 */
public class KeyDerivation {

    /**
     * The HMAC algorithm used for both HKDF-Extract and HKDF-Expand phases.
     * HMAC-SHA256 produces a 32-byte output, which matches the Ed25519 seed length.
     */
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * Derive a 32-byte (256-bit) key from the provided context string.
     *
     * <p>The context string is the sole input that differentiates derived keys.
     * For example, passing {@code "my-secret:access"} and {@code "my-secret:refresh"}
     * will produce two completely different 32-byte keys, both deterministic.</p>
     *
     * @param context the context string used for deterministic key derivation
     * @return a 32-byte array suitable for Ed25519 seed derivation
     * @throws RuntimeException if HMAC-SHA256 is not available in the runtime
     */
    public static byte[] derive(final String context) {
        try {
            return hkdf(context, 32);
        } catch (final GeneralSecurityException e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) with zero IKM and zero salt.
     *
     * <p><strong>Extract phase:</strong> HMAC-SHA256 is initialised with a zero-byte salt
     * and fed a zero-byte IKM (input keying material), producing a pseudorandom key (PRK).
     * Since there is no external secret, the PRK is fixed — all entropy comes from the
     * context string in the expand phase.</p>
     *
     * <p><strong>Expand phase:</strong> the PRK is used as the HMAC key, and the context
     * string (UTF-8 encoded) is fed as the info parameter along with a single-byte counter
     * ({@code 0x01}). This produces the output keying material (OKM), which is truncated
     * to the requested key length.</p>
     *
     * <p>The PRK is wiped from memory immediately after use.</p>
     *
     * @param context   the context string that differentiates derived keys
     * @param keyLength the desired output key length in bytes (must not exceed 32)
     * @return the derived key material truncated to {@code keyLength} bytes
     * @throws GeneralSecurityException if HMAC-SHA256 is not available
     */
    private static byte[] hkdf(final String context, final int keyLength) throws GeneralSecurityException {
        // ===== HKDF-Extract (zero IKM, zero salt) =====
        // Initialise HMAC with a zero-byte salt of the same length as the hash output.
        final Mac mac = Mac.getInstance(HMAC_ALGORITHM);

        final byte[] salt = new byte[mac.getMacLength()];
        mac.init(new SecretKeySpec(salt, HMAC_ALGORITHM));

        // Feed zero-byte IKM — no external secret, the context string provides differentiation.
        final byte[] ikm = new byte[mac.getMacLength()];
        final byte[] prk = mac.doFinal(ikm);

        // ===== HKDF-Expand (single block) =====
        // Re-key HMAC with the PRK and expand using the context string + counter byte.
        mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));

        // The context string is the info parameter — this is what makes each derived key unique.
        mac.update(context.getBytes(StandardCharsets.UTF_8));

        // Counter byte 0x01 — single block expansion (sufficient for up to 32 bytes).
        mac.update((byte) 0x01);

        final byte[] okm = mac.doFinal();

        // Wipe the PRK from memory immediately after expansion.
        Arrays.fill(prk, (byte) 0);

        return Arrays.copyOf(okm, keyLength);
    }
}