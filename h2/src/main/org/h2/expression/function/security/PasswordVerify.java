package org.h2.expression.function.security;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.FunctionN;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValueBoolean;
import org.h2.value.ValuePassword;

public final class PasswordVerify extends FunctionN {
    public static final String NAME = "PASSWORD_VERIFY";
    public PasswordVerify(Expression... args) { super(args); }
    @Override public Value getValue(SessionLocal s) {
        Value plain = args[0].getValue(s);
        Value pass  = args[1].getValue(s);
        if (pass.getValueType() != org.h2.value.Value.PASSWORD) {
            throw DbException.getInvalidValueException(NAME + " expected PASSWORD", pass);
        }
        boolean ok = ((ValuePassword) pass.convertTo(TypeInfo.TYPE_PASSWORD, null, false))
                .verify(plain.getString().toCharArray());
        return ValueBoolean.get(ok);
    }
    @Override public TypeInfo getType() { return TypeInfo.BOOLEAN; }
}
