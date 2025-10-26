package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.Function1;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValuePassword;
import org.h2.value.ValueVarchar;

/** PASSWORD_ALGO(pass) -> VARCHAR */
public final class PasswordAlgo extends Function1 {

    public static final String NAME = "PASSWORD_ALGO";

    public PasswordAlgo(Expression arg) {
        super(arg);
    }

    @Override
    public Value getValue(SessionLocal session) {
        Value v = arg.getValue(session);
        ValuePassword pw = (ValuePassword)
                v.convertTo(TypeInfo.getTypeInfo(Value.PASSWORD), session, false);
        return ValueVarchar.get(pw.algoName(), session);
    }

    @Override
    public TypeInfo getType() {
        return TypeInfo.getTypeInfo(Value.VARCHAR);
    }

    /** NEW REQUIRED METHOD */
    @Override
    public String getName() {
        return NAME;
    }

    /** also required by Function1 */
    @Override
    public Expression optimize(SessionLocal session) {
        return this;
    }
}
