package org.h2.expression.function.security;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.FunctionN;
import org.h2.message.DbException;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValuePassword;
import org.h2.value.ValueVarchar;

public final class PasswordAlgo extends FunctionN {
    public static final String NAME = "PASSWORD_ALGO";
    public PasswordAlgo(Expression... args) { super(args); }
    @Override public Value getValue(SessionLocal s) {
        Value pass = args[0].getValue(s);
        if (pass.getValueType() != org.h2.value.Value.PASSWORD) {
            throw DbException.getInvalidValueException(NAME + " expected PASSWORD", pass);
        }
        String algo = ((ValuePassword) pass.convertTo(TypeInfo.TYPE_PASSWORD, null, false)).algoName();
        return ValueVarchar.get(algo);
    }
    @Override public TypeInfo getType() { return TypeInfo.VARCHAR; }
}
