/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security.service.entity
 *@Date 2018/7/26
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder(builderClassName = "Builder", toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Long id;
    private Long orgId;
    private Long userId;
//    private String nationalCode;
//    private String mobile;
//    private String email;
    private String password;
    private String snow;
    private String tradePassword;
    private String tradeSnow;
    private String ip;
    private String gaKey;
    private Integer userStatus;
    private Integer apiLevel;
    private Long created;
    private Long updated;

    public String getCacheKey() {
        return orgId + "-" + userId;
    }

}
