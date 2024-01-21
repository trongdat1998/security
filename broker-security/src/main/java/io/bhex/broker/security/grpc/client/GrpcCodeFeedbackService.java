package io.bhex.broker.security.grpc.client;

import io.bhex.base.common.CodeFeedbackRequest;
import io.bhex.base.common.MessageServiceGrpc;
import io.bhex.broker.common.grpc.client.annotation.PrometheusMetrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
@PrometheusMetrics
public class GrpcCodeFeedbackService extends GrpcBaseService {

    @Resource(name = "asyncTaskExecutor")
    private TaskExecutor taskExecutor;


    public void codeFeedback(CodeFeedbackRequest codeFeedbackRequest) {
        MessageServiceGrpc.MessageServiceBlockingStub stub = grpcClientConfig.messageServiceBlockingStub(codeFeedbackRequest.getOrgId());
        CompletableFuture.runAsync(() -> {
            try {
                stub.codeFeedback(codeFeedbackRequest);
            } catch (Exception e) {
                log.error("CodeFeedback Exception", e);
            }
        }, taskExecutor);
    }

}
