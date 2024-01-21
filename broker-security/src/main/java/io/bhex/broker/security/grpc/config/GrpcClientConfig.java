/*
 ************************************
 * @项目名称: broker
 * @文件名称: GrcpClientConfig
 * @Date 2018/05/22
 * @Author will.zhao@bhex.io
 * @Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 * 注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 **************************************
 */
package io.bhex.broker.security.grpc.config;

import io.bhex.base.common.MailServiceGrpc;
import io.bhex.base.common.MessageServiceGrpc;
import io.bhex.base.common.SmsServiceGrpc;
import io.bhex.base.grpc.client.channel.IGrpcClientPool;
import io.bhex.broker.common.entity.GrpcChannelInfo;
import io.bhex.broker.grpc.broker.BrokerServiceGrpc;
import io.bhex.broker.grpc.gateway.BrokerAuthServiceGrpc;
import io.bhex.broker.grpc.notice.NoticeTemplateServiceGrpc;
import io.bhex.broker.security.SecurityProperties;
import io.grpc.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@ConditionalOnProperty(name = "security.proxy" , havingValue = "false")
public class GrpcClientConfig {

    static final String COMMON_SERVER_CHANNEL_NAME = "commonServer";

    static final String BROKER_SERVER_CHANNEL_NAME = "brokerServer";

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private IGrpcClientPool pool;

    Long stubDeadline;

    @PostConstruct
    public void init() throws Exception {
        stubDeadline = securityProperties.getGrpcClient().getStubDeadline();
        List<GrpcChannelInfo> channelInfoList = securityProperties.getGrpcClient().getChannelInfo();
        for (GrpcChannelInfo channelInfo : channelInfoList) {
            pool.setShortcut(channelInfo.getChannelName(), channelInfo.getHost(), channelInfo.getPort());
        }
    }

    public SmsServiceGrpc.SmsServiceBlockingStub smsServiceBlockingStub(Long orgId) {
//        Channel channel = channelMap.get(COMMON_SERVER_CHANNEL_NAME);
        Channel channel = pool.borrowChannel(COMMON_SERVER_CHANNEL_NAME);
        return SmsServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }

    public MessageServiceGrpc.MessageServiceBlockingStub messageServiceBlockingStub(Long orgId) {
//        Channel channel = channelMap.get(COMMON_SERVER_CHANNEL_NAME);
        Channel channel = pool.borrowChannel(COMMON_SERVER_CHANNEL_NAME);
        return MessageServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }

    public MailServiceGrpc.MailServiceBlockingStub mailServiceBlockingStub(Long orgId) {
//        Channel channel = channelMap.get(COMMON_SERVER_CHANNEL_NAME);
        Channel channel = pool.borrowChannel(COMMON_SERVER_CHANNEL_NAME);
        return MailServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }

    public NoticeTemplateServiceGrpc.NoticeTemplateServiceBlockingStub noticeTemplateServiceBlockingStub() {
//        Channel channel = channelMap.get(BROKER_SERVER_CHANNEL_NAME);
        Channel channel = pool.borrowChannel(BROKER_SERVER_CHANNEL_NAME);
        return NoticeTemplateServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }

    public BrokerServiceGrpc.BrokerServiceBlockingStub brokerServiceBlockingStub() {
//        Channel channel = channelMap.get(BROKER_SERVER_CHANNEL_NAME);
        Channel channel = pool.borrowChannel(BROKER_SERVER_CHANNEL_NAME);
        return BrokerServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }


    public BrokerAuthServiceGrpc.BrokerAuthServiceBlockingStub brokerAuthServiceBlockingStub() {
        Channel channel = pool.borrowChannel(BROKER_SERVER_CHANNEL_NAME);
        return BrokerAuthServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS);
    }

}


