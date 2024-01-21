/**********************************
 *@项目名称: broker-security
 *@文件名称: io.bhex.broker.security.service.entity
 *@Date 2018/7/23
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
public class UserPwdChangeLog {

    private Long id;
    private Long userId;
    private Integer changeType;
    private String oldPassword;
    private String oldSnow;
    private String newPassword;
    private String newSnow;
    private Long created;

}
