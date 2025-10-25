package org.h2.expression.function.security;

import org.h2.engine.SessionLocal;
import org.h2.expression.Expression;
import org.h2.expression.function.FunctionN;
import org.h2.value.TypeInfo;
import org.h2.value.Value;
import org.h2.value.ValuePassword;

public final class ToPassword extends FunctionN {
    public static final String NAME = "TO_PASSWORD";
    public ToPassword(Expression... args) { super(args); }
    @Override public Value getValue(SessionLocal s) {
        Value v0 = args[0].getValue(s);
        int cost = (args.length >= 2) ? args[1].getValue(s).getInt() : 12;
        return ValuePassword.fromString(v0.getString(), cost);
    }
    @Override public TypeInfo getType() { return TypeInfo.TYPE_PASSWORD; }
    @Override public boolean isDeterministic() { return false; } // random salt
}
