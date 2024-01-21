/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security.grpc.client
 *@Date 2018/9/9
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.grpc.client;

import io.bhex.broker.common.grpc.client.annotation.NoGrpcLog;
import io.bhex.broker.common.grpc.client.annotation.PrometheusMetrics;
import io.bhex.broker.grpc.common.Header;
import io.bhex.broker.grpc.notice.NoticeTemplateServiceGrpc;
import io.bhex.broker.grpc.notice.QueryVerifyCodeTemplateRequest;
import io.bhex.broker.grpc.notice.QueryVerifyCodeTemplateResponse;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@PrometheusMetrics
public class GrpcNoticeTemplateService extends GrpcBaseService {

    @NoGrpcLog
    public QueryVerifyCodeTemplateResponse queryVerifyCodeTemplate(Header header, QueryVerifyCodeTemplateRequest request) {
        NoticeTemplateServiceGrpc.NoticeTemplateServiceBlockingStub stub = grpcClientConfig.noticeTemplateServiceBlockingStub();
        try {
            if (!request.hasHeader()) {
                request = request.toBuilder().setHeader(header).build();
            }
            return stub.queryVerifyCodeTemplate(request);
        } catch (StatusRuntimeException e) {
            log.error("{}", printStatusRuntimeException(e));
            throw commonStatusRuntimeException(e);
        }
    }

}
