/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security
 *@Date 2018/7/25
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security;

import io.bhex.base.idgen.api.ISequenceGenerator;
import io.bhex.base.idgen.enums.DataCenter;
import io.bhex.base.idgen.snowflake.SnowflakeGenerator;
import io.bhex.base.mysql.BHMysqlDataSource;
import io.bhex.broker.common.grpc.client.aspect.GrpcLogAspect;
import io.bhex.broker.common.grpc.client.aspect.PrometheusMetricsAspect;
import io.lettuce.core.ReadFrom;
import io.prometheus.client.hotspot.DefaultExports;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.LettuceClientConfigurationBuilderCustomizer;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.task.TaskExecutor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import javax.sql.DataSource;

@SpringBootApplication(scanBasePackages = {"io.bhex"})
@EnableScheduling
@EnableAsync
@Slf4j
public class SecurityApplication {

    static {
        // set max netty directMemory to 1G
        System.setProperty("io.netty.maxDirectMemory", String.valueOf(1024 * 1024 * 1024L));
        DefaultExports.initialize();
    }

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource")
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    public DataSource dataSource(DataSourceProperties dataSourceProperties) {
        return dataSourceProperties.initializeDataSourceBuilder().type(BHMysqlDataSource.class).build();
    }

    @Bean
    public SecurityInitializer brokerInitializer() {
        return new SecurityInitializer();
    }

//    @Bean
//    public SecurityProperties securityProperties() {
//        return new SecurityProperties();
//    }

    @Bean
    public GrpcLogAspect grpcLogAspect() {
        return new GrpcLogAspect();
    }

    @Bean
    public PrometheusMetricsAspect prometheusMetricsAspect() {
        return new PrometheusMetricsAspect();
    }

    @Bean
    public LettuceClientConfigurationBuilderCustomizer lettuceCustomizer() {
//        ClusterTopologyRefreshOptions topologyRefreshOptions = ClusterTopologyRefreshOptions.builder()
////                .enablePeriodicRefresh()
////                .enablePeriodicRefresh(Duration.ofSeconds(5))
//                .enableAllAdaptiveRefreshTriggers()
//                .adaptiveRefreshTriggersTimeout(Duration.ofSeconds(5))
//                .build();
//
//        ClusterClientOptions clientOptions = ClusterClientOptions.builder()
//                .topologyRefreshOptions(topologyRefreshOptions)
//                .build();

        return clientConfigurationBuilder -> clientConfigurationBuilder.readFrom(ReadFrom.REPLICA_PREFERRED);
    }

    @Bean
    public ISequenceGenerator sequenceGenerator(StringRedisTemplate redisTemplate) {
        long workId;
        try {
            workId = redisTemplate.opsForValue().increment("broker-security-idGenerator-wordId") % 128;
        } catch (Exception e) {
            workId = RandomUtils.nextLong(0, 128);
            log.error("getIdGeneratorWorkId from redis occurred exception. set a random workId:{}", workId);
        }
        log.info("use workId:{} for IdGenerator", workId);
        return SnowflakeGenerator.newInstance(DataCenter.DC1.value(), workId);
    }

    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(10);
        scheduler.setThreadNamePrefix("TaskScheduler-");
        scheduler.setAwaitTerminationSeconds(10);
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        return scheduler;
    }

    @Bean
    public TaskExecutor asyncTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(20);
        executor.setMaxPoolSize(100);
        executor.setQueueCapacity(64);
        executor.setThreadNamePrefix("asyncTaskExecutor-");
        executor.setAwaitTerminationSeconds(10);
        executor.setWaitForTasksToCompleteOnShutdown(true);
        return executor;
    }

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
