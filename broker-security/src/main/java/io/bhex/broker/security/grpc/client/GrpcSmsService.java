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
public class GrpcSmsService extends GrpcBaseService {

    public boolean sendSmsVerifyCode(SmsRequest smsRequest) {
        SmsServiceGrpc.SmsServiceBlockingStub stub = grpcClientConfig.smsServiceBlockingStub(smsRequest.getOrgId());
        try {
            return stub.send(smsRequest).getSuccess();
        } catch (Exception e) {
            log.error("SendSmsVerifyCode Exception", e);
            return false;
        }
    }

    public boolean sendSmsVerifyCode(SendSmsRequest sendSmsRequest) {
        SmsServiceGrpc.SmsServiceBlockingStub stub = grpcClientConfig.smsServiceBlockingStub(sendSmsRequest.getOrgId());
        try {
            return stub.sendSms(sendSmsRequest).getSuccess();
        } catch (Exception e) {
            log.error("SendSmsVerifyCode Exception", e);
            return false;
        }
    }

    public boolean sendSmsVerifyCode(SimpleSMSRequest simpleSMSRequest) {
        MessageServiceGrpc.MessageServiceBlockingStub stub = grpcClientConfig.messageServiceBlockingStub(simpleSMSRequest.getOrgId());
        try {
            return stub.sendSimpleSMS(simpleSMSRequest).getSuccess();
        } catch (Exception e) {
            log.error("sendSmsNotice Exception", e);
            return false;
        }
    }

}
