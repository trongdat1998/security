/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security.service.entity
 *@Date 2018/8/6
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
public class ApiKey {

    private Long id;
    private Long orgId;
    private Long userId;
    private Long accountId;
    private Integer accountType;
    private Integer accountIndex;
    private String accountName;
    private String apiKey;
    private String secretKey;
    private String keySnow;
    private String tag;
    private String ipWhiteList;
    private Integer type;
    private Integer level;
    private Integer specialPermission;
    private Integer createForUser;
    private Integer status;
    private Long created;
    private Long updated;
    private Integer secretKeySeenTimesByOrg; //授权账户secretkey被查看次数

}
