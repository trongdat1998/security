package io.bhex.broker.security.uitl;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.bhex.broker.grpc.common.Header;
import io.bhex.broker.grpc.gateway.GetBrokerAuthByOrgIdRequest;
import io.bhex.broker.grpc.gateway.GetBrokerAuthByOrgIdResponse;
import io.bhex.broker.security.grpc.client.GrpcBrokerAuthService;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.springframework.context.ApplicationContext;

import java.util.concurrent.*;

/**
 * @author wangsc
 * @description org认证缓存（只缓存加签串）
 * @date 2020-06-05 14:43
 */
@Slf4j
public class BrokerAuthUtil {

    /**
     * 缓存加签串最多5分钟
     */
    private static final int BROKER_AUTH_CACHE_INVALID_MINUTES = 5;
    /**
     * 强制刷新的保护时间 毫秒
     */
    private static final int REFRESH_INTERVAL_MILLISECONDS = 30 * 1000;

    private static ApplicationContext applicationContext;

    private static LoadingCache<Long, BrokerApiAuth> brokerAuthCache = CacheBuilder.newBuilder()
            .expireAfterWrite(BROKER_AUTH_CACHE_INVALID_MINUTES, TimeUnit.MINUTES)
            .build(new CacheLoader<Long, BrokerApiAuth>() {
                @Override
                public BrokerApiAuth load(Long orgId) {
                    //从broker-server获取认证串
                    return getAtomicBrokerAuth(orgId);
                }
            });

    /**
     * 强制刷新间隔（用户orgId不存在的保护)
     */
    private static final ConcurrentMap<Long, Long> RE_FRESH_INTERVAL_CACHE = new ConcurrentHashMap<>();

    private static BrokerApiAuth reFreshBrokerAuth(Long orgId) {
        Long time = RE_FRESH_INTERVAL_CACHE.get(orgId);
        if (time == null || time < System.currentTimeMillis()) {
            //从broker-server获取认证串
            BrokerApiAuth brokerAuth = getAtomicBrokerAuth(orgId);
            if (brokerAuth != null) {
                brokerAuthCache.put(orgId, brokerAuth);
            }
            return brokerAuth;
        } else {
            return null;
        }
    }


    public static void init(ApplicationContext applicationContext) {
        BrokerAuthUtil.applicationContext = applicationContext;
        //定时清理reFreshIntervalCache
        ScheduledExecutorService scheduler = new ScheduledThreadPoolExecutor(1,
                new BasicThreadFactory.Builder().namingPattern("CleanRefreshInterval_%d").daemon(false).build());
        scheduler.scheduleAtFixedRate(() -> {
            long removeTime = System.currentTimeMillis() - 10 * 60 * 1000;
            RE_FRESH_INTERVAL_CACHE.entrySet().stream().filter(refresh -> refresh.getValue() < removeTime)
                    .forEach(refresh -> RE_FRESH_INTERVAL_CACHE.remove(refresh.getKey(), refresh.getValue()));
        }, 2, 2, TimeUnit.HOURS);
    }

    private static BrokerApiAuth getAtomicBrokerAuth(Long orgId) {
        try {
            GetBrokerAuthByOrgIdResponse getBrokerAuthByOrgIdResponse = applicationContext.getBean(GrpcBrokerAuthService.class)
                    .getBrokerAuthByOrgId(GetBrokerAuthByOrgIdRequest
                            .newBuilder()
                            .setHeader(Header.newBuilder().setOrgId(orgId).build())
                            .build());
            if (getBrokerAuthByOrgIdResponse.getRet() == 0) {
                GetBrokerAuthByOrgIdResponse.BrokerOrgAuth brokerOrgAuth = getBrokerAuthByOrgIdResponse.getBrokerOrgAuth();
                return BrokerApiAuth.builder().apiKey(brokerOrgAuth.getApiKey()).authData(brokerOrgAuth.getAuthData()).refreshTime(brokerOrgAuth.getRefreshTime()).build();
            } else {
                //正常不存在限制再次获取
                RE_FRESH_INTERVAL_CACHE.put(orgId, System.currentTimeMillis() + REFRESH_INTERVAL_MILLISECONDS);
                return null;
            }
        } catch (Exception e) {
            log.warn("get broker org auth error! {} {}", orgId, e.getMessage());
            return null;
        }
    }

    /**
     * 检查获取认证
     *
     * @param orgId
     * @return
     */
    public static BrokerApiAuth getBrokerAuth(Long orgId) {
        try {
            if (orgId == null) {
                return null;
            }
            long currentTimeMillis = System.currentTimeMillis();
            BrokerApiAuth brokerAuth = brokerAuthCache.get(orgId);
            if (brokerAuth == null || brokerAuth.refreshTime < currentTimeMillis) {
                return reFreshBrokerAuth(orgId);
            } else {
                return brokerAuth;
            }
        } catch (Exception e) {
            log.warn("Get broker auth error! {} {}", orgId, e.getMessage());
            return null;
        }
    }

    /**
     * broker认证缓存
     */
    @Data
    @Builder
    public static class BrokerApiAuth {
        private String apiKey;
        /**
         * 刷新时间（加签时间+4分钟）
         */
        private long refreshTime;
        /**
         * 认证串
         */
        private String authData;
    }
}
