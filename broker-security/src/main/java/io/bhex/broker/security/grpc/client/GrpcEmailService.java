/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security.grpc.client
 *@Date 2018/8/14
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.grpc.client;

import io.bhex.base.common.*;
import io.bhex.broker.common.grpc.client.annotation.PrometheusMetrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@PrometheusMetrics
public class GrpcEmailService extends GrpcBaseService {

    public boolean sendEmailVerifyCode(MailRequest mailRequest) {
        MailServiceGrpc.MailServiceBlockingStub stub = grpcClientConfig.mailServiceBlockingStub(mailRequest.getOrgId());
        try {
            return stub.send(mailRequest).getSuccess();
        } catch (Exception e) {
            log.error("SendEmailVerifyCode Exception", e);
            return false;
        }
    }

    public boolean sendEmailVerifyCode(SendMailRequest mailRequest) {
        MailServiceGrpc.MailServiceBlockingStub stub = grpcClientConfig.mailServiceBlockingStub(mailRequest.getOrgId());
        try {
            return stub.sendMail(mailRequest).getSuccess();
        } catch (Exception e) {
            log.error("SendEmailVerifyCode Exception", e);
            return false;
        }
    }

    public boolean sendEmailVerifyCode(SimpleMailRequest simpleMailRequest) {
        MessageServiceGrpc.MessageServiceBlockingStub stub = grpcClientConfig.messageServiceBlockingStub(simpleMailRequest.getOrgId());
        try {
            return stub.sendSimpleMail(simpleMailRequest).getSuccess();
        } catch (Exception e) {
            log.error("SendEmailVerifyCode Exception", e);
            return false;
        }
    }
}
