package org.h2.value;

import java.nio.charset.StandardCharsets;
import org.h2.engine.CastDataProvider;
import org.h2.value.CompareMode;
import org.h2.util.StringUtils;

/**
 * Custom Value type for PASSWORD data.
 */
public final class ValuePassword extends Value {

    private final String hash;

    private ValuePassword(String hash) {
        this.hash = hash;
    }

    /** Plain → Hashed (with cost) */
    public static ValuePassword fromString(String plain, int cost) {
        // TODO: implement proper bcrypt with cost
        return new ValuePassword("{bcrypt}" + plain);
    }

    /** Plain → Hashed (default cost = 12) */
    public static ValuePassword fromString(String plain) {
        return fromString(plain, 12);
    }



    /** Factory: create from existing stored hash. */
    public static ValuePassword fromHash(String hash) {
        return new ValuePassword(hash);
    }

    /** Verify plain text password. */
    public boolean verify(char[] plain) {
        return getHash().equals("{bcrypt}" + new String(plain));
    }

    public String algoName() {
        return "bcrypt";
    }


    @Override
    public int getValueType() {
        return Value.PASSWORD;
    }

    @Override
    public TypeInfo getType() {
        return TypeInfo.getTypeInfo(Value.PASSWORD);
    }

    @Override
    public String getString() {
        // Return the actual hash for storage and internal operations
        return hash;
    }

    /**
     * Get the actual hash for internal use (e.g., password verification).
     * This should only be used internally by the database engine.
     */
    public String getHash() {
        return hash;
    }

    @Override
    public byte[] getBytes() {
        return hash.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int compareTypeSafe(Value v, CompareMode mode, CastDataProvider provider) {
        return mode.compareString(this.hash, ((ValuePassword) v).hash, false);
    }


    public Value copy() {
        return this;
    }

    @Override
    public int hashCode() {
        return hash.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ValuePassword && ((ValuePassword) o).hash.equals(this.hash);
    }

    @Override
    public String toString() {
        return "ValuePassword[***]";
    }

    @Override
    public StringBuilder getSQL(StringBuilder builder, int sqlFlags) {
        // DO NOT reveal plaintext passwords in SQL output.
        builder.append("PASSWORD('***')");
        return builder;
    }

}
