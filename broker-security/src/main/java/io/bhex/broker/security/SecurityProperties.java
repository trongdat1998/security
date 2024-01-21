/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security
 *@Date 2018/7/27
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security;

import io.bhex.broker.common.entity.GrpcClientProperties;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private String secretKey = "";
//    private Long tokenValidityInSeconds = 3600 * 24L;
    private GrpcClientProperties grpcClient = new GrpcClientProperties();

}
