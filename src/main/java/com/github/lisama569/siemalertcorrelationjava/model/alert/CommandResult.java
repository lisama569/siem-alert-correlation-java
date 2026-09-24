package com.github.lisama569.siemalertcorrelationjava.model.alert;

/** 处置命令结果：成功带新快照，失败带可区分原因。 */
public record CommandResult(
        boolean success,
        Alert alert,
        TransitionFailure failure,
        String detail) {

    public static CommandResult ok(Alert alert) {
        return new CommandResult(true, alert, null, null);
    }

    public static CommandResult fail(Alert current, TransitionFailure failure, String detail) {
        return new CommandResult(false, current, failure, detail);
    }
}
