package io.bhex.broker.security.domain;

import io.bhex.broker.common.exception.BrokerErrorCode;
import io.bhex.broker.common.exception.BrokerException;
import io.bhex.broker.grpc.common.AccountTypeEnum;

public enum AccountType {
    UNKNOWN(0, ""),
    MAIN(1, "main"), //主账户
    OPTION(2, "option"), //期权账户
    FUTURES(3, "futures"); //期货账户

    private final int value;
    private final String type;

    AccountType(int value, String type) {
        this.value = value;
        this.type = type;
    }

    public static AccountType fromValue(int value) {
        for (AccountType accountType : AccountType.values()) {
            if (accountType.value == value) {
                return accountType;
            }
        }
        return UNKNOWN;
    }

    public static AccountType fromAccountTypeEnum(AccountTypeEnum accountTypeEnum) {
        switch (accountTypeEnum) {
            case COIN:
                return MAIN;
            case OPTION:
                return OPTION;
            case FUTURE:
                return FUTURES;
            default:
                throw new BrokerException(BrokerErrorCode.PARAM_INVALID);
        }
    }

    public AccountTypeEnum toAccountTypeEnum() {
        switch (this) {
            case MAIN:
                return AccountTypeEnum.COIN;
            case OPTION:
                return AccountTypeEnum.OPTION;
            case FUTURES:
                return AccountTypeEnum.FUTURE;
            default:
                throw new BrokerException(BrokerErrorCode.PARAM_INVALID);
        }
    }

    public int value() {
        return this.value;
    }

    public String type() {
        return this.type;
    }
}
