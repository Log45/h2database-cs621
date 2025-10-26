package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.FunctionN;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValueBoolean;
import org.h2.value.ValuePassword;
import org.h2.value.ValueVarchar;

/** Provides SQL functions:
 *  TO_PASSWORD(text [, cost])
 *  PASSWORD_VERIFY(text, password)
 *  PASSWORD_ALGO(password)
 */
public final class PasswordFunctions {

    /** TO_PASSWORD(plain [, cost]) -> PASSWORD */
    public static final class ToPassword extends FunctionN {

        public ToPassword(Expression... args) {
            super(args);
        }

        @Override
        public Value getValue(SessionLocal session) {
            Value plain = args[0].getValue(session);
            int cost = (args.length >= 2) ? args[1].getValue(session).getInt() : 12;
            return ValuePassword.fromString(plain.getString(), cost);
        }

        @Override
        public TypeInfo getType() {
            return TypeInfo.getTypeInfo(Value.PASSWORD);
        }

        @Override
        public Expression optimize(SessionLocal session) {
            for (int i = 0; i < args.length; i++) {
                args[i] = args[i].optimize(session);
            }
            return this;
        }

        @Override
        public String getName() {
            return "TO_PASSWORD";
        }
    }

    /** PASSWORD_VERIFY(plain, pass) -> BOOLEAN */
    public static final class Verify extends FunctionN {

        public Verify(Expression... args) {
            super(args);
        }

        @Override
        public Value getValue(SessionLocal session) {
            Value plain = args[0].getValue(session);
            Value pass = args[1].getValue(session);

            if (pass.getValueType() != Value.PASSWORD) {
                throw DbException.getInvalidValueException("PASSWORD_VERIFY expected PASSWORD", pass);
            }

            boolean ok = ((ValuePassword) pass.convertTo(
                    TypeInfo.getTypeInfo(Value.PASSWORD), null, false))
                    .verify(plain.getString().toCharArray());

            return ValueBoolean.get(ok);
        }

        @Override
        public TypeInfo getType() {
            return TypeInfo.getTypeInfo(Value.BOOLEAN);
        }

        @Override
        public Expression optimize(SessionLocal session) {
            for (int i = 0; i < args.length; i++) {
                args[i] = args[i].optimize(session);
            }
            return this;
        }

        @Override
        public String getName() {
            return "PASSWORD_VERIFY";
        }
    }

    /** PASSWORD_ALGO(pass) -> VARCHAR */
    public static final class Algo extends FunctionN {

        public Algo(Expression... args) {
            super(args);
        }

        @Override
        public Value getValue(SessionLocal session) {
            Value pass = args[0].getValue(session);

            if (pass.getValueType() != Value.PASSWORD) {
                throw DbException.getInvalidValueException("PASSWORD_ALGO expected PASSWORD", pass);
            }

            String algo = ((ValuePassword) pass.convertTo(
                    TypeInfo.getTypeInfo(Value.PASSWORD), null, false))
                    .algoName();

            return ValueVarchar.get(algo);
        }

        @Override
        public TypeInfo getType() {
            return TypeInfo.getTypeInfo(Value.VARCHAR);
        }

        @Override
        public Expression optimize(SessionLocal session) {
            for (int i = 0; i < args.length; i++) {
                args[i] = args[i].optimize(session);
            }
            return this;
        }

        @Override
        public String getName() {
            return "PASSWORD_ALGO";
        }
    }
}
