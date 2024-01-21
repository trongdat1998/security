/**********************************
 *@项目名称: broker-parent
 *@文件名称: io.bhex.broker
 *@Date 2018/7/15
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.metrics.prometheus.PrometheusMetricsTrackerFactory;
import io.bhex.base.grpc.client.channel.IGrpcClientPool;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.ContextStoppedEvent;
import org.springframework.context.event.EventListener;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.sql.DataSource;

@Slf4j
public class SecurityInitializer {

    @Resource
    private DataSource dataSource;

    @Resource
    private IGrpcClientPool pool;

    @PostConstruct
    public void init() {
        if (this.dataSource instanceof HikariDataSource) {
            ((HikariDataSource) this.dataSource).setMetricsTrackerFactory(new PrometheusMetricsTrackerFactory());
        }
    }

    @EventListener(value = {ContextStoppedEvent.class})
    public void contextStoppedAlert() {
        log.warn("[ALERT] context is stopped, please check!!!");
        pool.shutdown();
    }

    @EventListener(value = {ContextClosedEvent.class})
    public void contextClosedAlert() {
        log.warn("[ALERT] context is closed, please check!!!");
        pool.shutdown();
    }

}
