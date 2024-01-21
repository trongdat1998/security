/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/7/26
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import io.bhex.broker.security.service.entity.User;
import io.bhex.broker.security.service.entity.UserBindGACheck;
import org.apache.ibatis.annotations.*;

@Mapper
public interface UserMapper {

    String COLUMNS = "id, org_id, user_id, password, trade_password, snow, trade_snow, ga_key, user_status, api_level, created, updated";
    String USER_BIND_GA_CHECK_COLUMNS = "id, org_id, user_id, ga_key, expired, created";

    @Insert(" INSERT INTO tb_user(org_id, user_id, password, snow, user_status, created, updated) "
            + " VALUES(#{orgId}, #{userId}, #{password}, #{snow}, #{userStatus}, #{created}, #{updated})")
    @Options(useGeneratedKeys = true, keyColumn = "id", keyProperty = "id")
    int insert(User user);

    @UpdateProvider(type = UserSqlProvider.class, method = "update")
    int update(User user);

    @Select(" SELECT " + COLUMNS + " FROM tb_user WHERE org_id=#{orgId} AND user_id=#{userId}")
    User getByUserId(@Param("orgId") Long orgId, @Param("userId") Long userId);

    @Insert(" INSERT INTO tb_user_bind_ga_check(org_id, user_id, ga_key, expired, created) "
            + "VALUES(#{orgId}, #{userId}, #{gaKey}, #{expired}, #{created})")
    @Options(useGeneratedKeys = true, keyColumn = "id", keyProperty = "id")
    int insertUserBindGACheck(UserBindGACheck userBindGACheck);

    @Select(" SELECT " + USER_BIND_GA_CHECK_COLUMNS + " FROM tb_user_bind_ga_check "
            + "WHERE org_id = #{orgId} AND user_id = #{userId} ORDER BY id DESC LIMIT 1 ")
    UserBindGACheck getLastBindGaCheck(@Param("orgId") Long orgId, @Param("userId") Long userId);

}
