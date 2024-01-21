/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/10/18
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import io.bhex.broker.security.service.entity.VerifyCode;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface VerifyCodeMapper {

    @Insert("INSERT INTO tb_verify_code_log VALUES(#{id}, #{orgId}, #{userId}, #{receiver}, #{type}, #{code}, #{content}, #{created})")
    int insert(VerifyCode verifyCode);

    @Select("Select id, code, content FROM tb_verify_code_log WHERE id=#{id}")
    VerifyCode get(Long id);

    @Select("Select id, code, type, content FROM tb_verify_code_log where receiver LIKE CONCAT('%', #{receiver}, '%') ORDER BY id DESC LIMIT 10")
    List<VerifyCode> queryByReceiver(String receiver);

}
