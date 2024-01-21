/**********************************
 *@项目名称: server-parent
 *@文件名称: io.bhex.broker.server.model
 *@Date 2018/9/9
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service.entity;

import lombok.Builder;
import lombok.Data;

@Data
@Builder(builderClassName = "Builder", toBuilder = true)
public class NoticeTemplate {

    private Long id;
    private Long orgId;
    private Integer noticeType;
    private String businessType;
    private String language;
    private Long templateId;
    private String templateContent;
    private Integer sendType;
    private String sign;
    private String subject;
    private Long created;
    private Long updated;

}
