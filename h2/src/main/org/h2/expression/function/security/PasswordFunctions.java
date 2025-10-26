package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.function.FunctionN;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValueBoolean;
import org.h2.value.ValuePassword;
import org.h2.value.ValueVarchar;

/** Registers TO_PASSWORD, PASSWORD_VERIFY, PASSWORD_ALGO. */
public final class PasswordFunctions {

    /** TO_PASSWORD(plain [, cost]) -> PASSWORD  */
    public static final class ToPassword extends FunctionN {
        public ToPassword() { super(new String[]{"TO_PASSWORD"}); }
        @Override public Value getValue(SessionLocal s) {
            Value v0 = args[0].getValue(s);
            int cost = (args.length >= 2) ? args[1].getValue(s).getInt() : 12;
            return ValuePassword.fromString(v0.getString(), cost);
        }
        @Override public TypeInfo getType() { return TypeInfo.TYPE_PASSWORD; }
        @Override public boolean isDeterministic() { return false; } // salt
    }

    /** PASSWORD_VERIFY(plain, pass) -> BOOLEAN */
    public static final class Verify extends FunctionN {
        public Verify() { super(new String[]{"PASSWORD_VERIFY"}); }
        @Override public Value getValue(SessionLocal s) {
            Value plain = args[0].getValue(s);
            Value pass  = args[1].getValue(s);
            if (pass.getValueType() != Value.PASSWORD) {
                throw DbException.getInvalidValueException("PASSWORD_VERIFY expected PASSWORD", pass);
            }
            boolean ok = ((ValuePassword) pass.convertTo(TypeInfo.TYPE_PASSWORD, null, false))
                    .verify(plain.getString().toCharArray());
            return ValueBoolean.get(ok);
        }
        @Override public TypeInfo getType() { return TypeInfo.BOOLEAN; }
    }

    /** PASSWORD_ALGO(pass) -> VARCHAR */
    public static final class Algo extends FunctionN {
        public Algo() { super(new String[]{"PASSWORD_ALGO"}); }
        @Override public Value getValue(SessionLocal s) {
            Value pass = args[0].getValue(s);
            if (pass.getValueType() != Value.PASSWORD) {
                throw DbException.getInvalidValueException("PASSWORD_ALGO expected PASSWORD", pass);
            }
            String algo = ((ValuePassword) pass.convertTo(TypeInfo.TYPE_PASSWORD, null, false)).algoName();
            return ValueVarchar.get(algo);
        }
        @Override public TypeInfo getType() { return TypeInfo.VARCHAR; }
    }
}
