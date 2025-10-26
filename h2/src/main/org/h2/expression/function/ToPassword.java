package org.h2.expression.function;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValuePassword;

public final class ToPassword extends FunctionN {

    public static final String NAME = "TO_PASSWORD";

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
        return this; // required override in H2 2.4
    }

    @Override
    public String getName() {
        return NAME; // required override in H2 2.4
    }
}
