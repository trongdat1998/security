/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security.grpc.client
 *@Date 2018/9/10
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.grpc.client;

import io.bhex.broker.common.grpc.client.annotation.GrpcLog;
import io.bhex.broker.common.grpc.client.annotation.NoGrpcLog;
import io.bhex.broker.common.grpc.client.annotation.PrometheusMetrics;
import io.bhex.broker.grpc.broker.BrokerServiceGrpc;
import io.bhex.broker.grpc.broker.QueryBrokerRequest;
import io.bhex.broker.grpc.broker.QueryBrokerResponse;
import io.bhex.broker.grpc.common.Header;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@GrpcLog
@PrometheusMetrics
public class GrpcBrokerService extends GrpcBaseService {

    @NoGrpcLog
    public QueryBrokerResponse queryBrokers(Header header, QueryBrokerRequest request) {
        BrokerServiceGrpc.BrokerServiceBlockingStub stub = grpcClientConfig.brokerServiceBlockingStub();
        try {
            if (!request.hasHeader()) {
                request = request.toBuilder().setHeader(header).build();
            }
            return stub.queryBrokers(request);
        } catch (StatusRuntimeException e) {
            log.error("{}", printStatusRuntimeException(e));
            throw commonStatusRuntimeException(e);
        }
    }

}
