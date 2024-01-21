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
import io.bhex.broker.security.SecurityProperties;
import io.bhex.broker.security.grpc.config.interceptor.RouteAuthCredentials;
import io.bhex.broker.security.uitl.BrokerAuthUtil;
import io.grpc.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component("grpcClientConfig")
@ConditionalOnProperty(name = "security.proxy", havingValue = "true")
public class GatewayGrpcClientConfig extends GrpcClientConfig {

    private static final String GATEWAY_SERVER_CHANNEL_NAME = "gatewayServer";

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private IGrpcClientPool pool;

    @Resource
    private ApplicationContext applicationContext;

    @PostConstruct
    @Override
    public void init() throws Exception {
        stubDeadline = securityProperties.getGrpcClient().getStubDeadline();
        List<GrpcChannelInfo> channelInfoList = securityProperties.getGrpcClient().getChannelInfo();
        for (GrpcChannelInfo channelInfo : channelInfoList) {
            pool.setShortcut(channelInfo.getChannelName(), channelInfo.getHost(), channelInfo.getPort());
        }
        BrokerAuthUtil.init(applicationContext);
    }

    @Override
    public SmsServiceGrpc.SmsServiceBlockingStub smsServiceBlockingStub(Long orgId) {
        Channel channel = pool.borrowChannel(GATEWAY_SERVER_CHANNEL_NAME);
        return SmsServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS)
                .withCallCredentials(new RouteAuthCredentials(COMMON_SERVER_CHANNEL_NAME, orgId));
    }

    @Override
    public MessageServiceGrpc.MessageServiceBlockingStub messageServiceBlockingStub(Long orgId) {
        Channel channel = pool.borrowChannel(GATEWAY_SERVER_CHANNEL_NAME);
        return MessageServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS)
                .withCallCredentials(new RouteAuthCredentials(COMMON_SERVER_CHANNEL_NAME, orgId));
    }

    @Override
    public MailServiceGrpc.MailServiceBlockingStub mailServiceBlockingStub(Long orgId) {
        Channel channel = pool.borrowChannel(GATEWAY_SERVER_CHANNEL_NAME);
        return MailServiceGrpc.newBlockingStub(channel).withDeadlineAfter(stubDeadline, TimeUnit.MILLISECONDS)
                .withCallCredentials(new RouteAuthCredentials(COMMON_SERVER_CHANNEL_NAME, orgId));
    }

}


