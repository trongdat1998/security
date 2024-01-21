package io.bhex.broker.security.service;

import io.bhex.broker.security.service.entity.UserPwdChangeLog;
import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**********************************
 *@项目名称: broker-security
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/7/23
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
@Mapper
interface UserPwdChangeLogMapper {

    @InsertProvider(type = UserPwdChangeLogSqlProvider.class, method = "insert")
    int insert(UserPwdChangeLog userPwdChangeLog);

    @Select(" SELECT * FROM tb_user_pwd_change_log WHERE user_id=#{userId} ORDER BY id DESC LIMIT 5")
    List<UserPwdChangeLog> queryChangePwdLogs(Long userId);

}
