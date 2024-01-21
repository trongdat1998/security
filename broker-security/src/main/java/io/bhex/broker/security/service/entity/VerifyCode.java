/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security.service.entity
 *@Date 2018/10/18
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
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyCode {

    private Long id;
    private Long orgId;
    private Long userId;
    private String receiver;
    private Integer type;
    private String code;
    private String content;
    private Long created;

}
