package io.bhex.broker.security.grpc.client;

import io.bhex.broker.grpc.gateway.*;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * @author wangsc
 * @description
 * @date 2020-06-06 11:31
 */
@Service
@Slf4j
public class GrpcBrokerAuthService extends GrpcBaseService {

    public GetBrokerAuthByOrgIdResponse getBrokerAuthByOrgId(GetBrokerAuthByOrgIdRequest request) {
        BrokerAuthServiceGrpc.BrokerAuthServiceBlockingStub stub = grpcClientConfig.brokerAuthServiceBlockingStub();
        try {
            return stub.getBrokerAuthByOrgId(request);
        } catch (StatusRuntimeException e) {
            log.error("getBrokerAuthByOrgId {}", printStatusRuntimeException(e));
            throw commonStatusRuntimeException(e);
        }
    }
}
