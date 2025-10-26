package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.FunctionN;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValueBoolean;
import org.h2.value.ValuePassword;

/**
 * PASSWORD_VERIFY(plain, hashed)
 */
public final class PasswordVerify extends FunctionN {

    public static final String NAME = "PASSWORD_VERIFY";

    public PasswordVerify(Expression... args) {
        super(args);
    }

    @Override
    public Value getValue(SessionLocal session) {
        Value plain = args[0].getValue(session);
        Value pass = args[1].getValue(session);

        if (pass.getValueType() != Value.PASSWORD) {
            throw DbException.getInvalidValueException(NAME + " expected PASSWORD", pass);
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
    public String getName() {
        return NAME;
    }

    /**
     * Required override because FunctionN inherits from Expression.
     */
    @Override
    public Expression optimize(SessionLocal session) {
        return this; // no compile-time reduction
    }
}
