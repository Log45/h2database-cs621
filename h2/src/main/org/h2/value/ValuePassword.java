package org.h2.value;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.h2.engine.SysProperties;
import org.h2.message.DbException;

/**
 * H2 runtime value for the SQL type PASSWORD.
 * Stored as: [ver(1)][algo(1)][cost(1)][saltLen(1)][salt...][hash...]
 * Algo: 1 = PBKDF2-HMAC-SHA256
 */
public final class ValuePassword extends Value {

    // ---- header constants ----
    private static final byte VER = 1;
    private static final byte ALGO_PBKDF2_SHA256 = 1;
    private static final int DEFAULT_COST = 12;       // work factor => iterations = 2^(10 + cost)
    private static final int DEFAULT_SALT_LEN = 16;   // bytes
    private static final int HASH_LEN = 32;           // 256-bit

    private static final SecureRandom RNG = new SecureRandom();

    private final byte[] blob;

    private ValuePassword(byte[] packed) {
        this.blob = packed;
    }

    // ---- factories ----
    public static ValuePassword fromPlain(char[] plain) {
        return fromPlain(plain, ALGO_PBKDF2_SHA256, DEFAULT_COST, DEFAULT_SALT_LEN);
    }

    public static ValuePassword fromPlain(char[] plain, int cost) {
        return fromPlain(plain, ALGO_PBKDF2_SHA256, cost, DEFAULT_SALT_LEN);
    }

    public static ValuePassword fromPlain(char[] plain, byte algo, int cost, int saltLen) {
        if (saltLen < 8 || saltLen > 64) {
            throw DbException.getInvalidValueException("saltLen", saltLen);
        }
        byte[] salt = new byte[saltLen];
        RNG.nextBytes(salt);
        byte[] hash = pbkdf2(plain, salt, cost);
        byte[] packed = pack(algo, cost, salt, hash);
        Arrays.fill(hash, (byte) 0);
        return new ValuePassword(packed);
    }

    public static ValuePassword get(byte[] blob) {
        validateBlob(blob);
        return new ValuePassword(Arrays.copyOf(blob, blob.length));
    }

    // ---- Value API ----
    @Override
    public int getValueType() {
        return Value.PASSWORD;
    }

    @Override
    public String getString() {
        return "*PASSWORD*";
    }

    @Override
    public byte[] getBytesNoCopy() {
        return blob;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(extractHash(blob));
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof ValuePassword)
                && constantTimeEquals(extractHash(this.blob), extractHash(((ValuePassword) o).blob));
    }

    @Override
    public int compareTypeSafe(Value v, CompareMode mode) {
        throw DbException.getUnsupportedException("PASSWORD not orderable");
    }

    @Override
    public boolean isMemory() {
        return true;
    }

    @Override
    public Value convertTo(TypeInfo targetType, CastDataProvider provider, boolean sanitize) {
        // BINARY / VARBINARY get the raw blob; VARCHAR returns masked
        switch (targetType.getValueType()) {
            case BYTES:
            case BINARY:
            case VARBINARY:
                return ValueVarbinary.get(getBytesNoCopy());
            case VARCHAR:
            case STRING:
            case STRING_IGNORECASE:
                return ValueVarchar.get(getString());
            case PASSWORD:
                return this;
            default:
                throw DbException.getUnsupportedException("Cannot cast PASSWORD to " + targetType.getDeclaredTypeName());
        }
    }

    // ---- helpers ----

    /** Return true if plain matches this password value. */
    public boolean verify(char[] plain) {
        Header h = header(blob);
        byte[] salt = extractSalt(blob);
        byte[] expected = extractHash(blob);
        byte[] actual = pbkdf2(plain, salt, h.cost);
        boolean eq = constantTimeEquals(expected, actual);
        Arrays.fill(actual, (byte) 0);
        return eq;
    }

    public String algoName() {
        Header h = header(blob);
        if (h.algo == ALGO_PBKDF2_SHA256) return "PBKDF2-HMAC-SHA256";
        return "UNKNOWN(" + h.algo + ")";
    }

    private static byte[] pack(byte algo, int cost, byte[] salt, byte[] hash) {
        byte[] out = new byte[4 + salt.length + hash.length];
        out[0] = VER;
        out[1] = algo;
        out[2] = (byte) cost;
        out[3] = (byte) salt.length;
        System.arraycopy(salt, 0, out, 4, salt.length);
        System.arraycopy(hash, 0, out, 4 + salt.length, hash.length);
        return out;
    }

    private static void validateBlob(byte[] b) {
        if (b == null || b.length < 4) throw DbException.getInvalidValueException("PASSWORD", "<header>");
        if (b[0] != VER) throw DbException.getInvalidValueException("PASSWORD ver", b[0]);
        int saltLen = b[3] & 0xff;
        if (4 + saltLen + HASH_LEN != b.length) {
            throw DbException.getInvalidValueException("PASSWORD blob length", b.length);
        }
    }

    private static Header header(byte[] b) {
        validateBlob(b);
        Header h = new Header();
        h.ver = b[0];
        h.algo = b[1];
        h.cost = b[2];
        h.saltLen = b[3] & 0xff;
        return h;
    }

    private static byte[] extractSalt(byte[] b) {
        int saltLen = b[3] & 0xff;
        return Arrays.copyOfRange(b, 4, 4 + saltLen);
    }

    private static byte[] extractHash(byte[] b) {
        int saltLen = b[3] & 0xff;
        return Arrays.copyOfRange(b, 4 + saltLen, b.length);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }

    private static byte[] pbkdf2(char[] plain, byte[] salt, int cost) {
        // cost -> iterations scaling; 2^(10+cost) ~ defaults near 4096-131072
        int iterations = 1 << Math.min(20, Math.max(10, 10 + cost));
        PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, HASH_LEN * 8);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw DbException.convert(e);
        } finally {
            spec.clearPassword();
        }
    }

    private static final class Header {
        byte ver, algo;
        int cost, saltLen;
    }

    // Convenience constructors for SQL functions
    public static ValuePassword fromString(String s) {
        return fromPlain(s.toCharArray());
    }
    public static ValuePassword fromString(String s, int cost) {
        return fromPlain(s.toCharArray(), cost);
    }
}
