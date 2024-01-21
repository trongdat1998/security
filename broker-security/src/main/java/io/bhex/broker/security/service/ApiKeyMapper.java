/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/8/6
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import io.bhex.broker.security.service.entity.ApiKey;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
interface ApiKeyMapper {

    String TABLE_NAME = "tb_api_key";
    String COLUMNS = "id, org_id, user_id, account_id, account_type, account_index, account_name, api_key, secret_key, " +
            "key_snow, tag, ip_white_list, type, level, special_permission, create_for_user, status, created, updated,secret_key_seen_times_by_org";

    @InsertProvider(type = ApiKeySqlProvider.class, method = "insertApiKey")
    @Options(useGeneratedKeys = true, keyColumn = "id", keyProperty = "id")
    int insert(ApiKey apiKey);

    @InsertProvider(type = ApiKeySqlProvider.class, method = "insertApiKeyLog")
    int insertLog(ApiKey apiKey);

    @UpdateProvider(type = ApiKeySqlProvider.class, method = "update")
    int update(ApiKey apiKey);

    @Delete(" DELETE FROM " + TABLE_NAME + " WHERE id=#{id}")
    int delete(@Param("id") Long id);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE id=#{id}")
    ApiKey getById(Long id);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE id=#{id} AND org_id=#{orgId} AND user_id=#{userId} AND create_for_user = 1")
    ApiKey getUserApiKeyById(@Param("id") Long id, @Param("orgId") Long orgId, @Param("userId") Long userId);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE api_key=#{apiKey}")
    ApiKey getByApiKey(String apiKey);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE org_id=#{orgId} AND user_id=#{userId} AND create_for_user = 1")
    List<ApiKey> queryByUserId(@Param("orgId") Long orgId, @Param("userId") Long userId);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE org_id=#{orgId} AND user_id=#{userId} AND account_id=#{accountId} AND create_for_user = 1")
    List<ApiKey> queryByAccountId(@Param("orgId") Long orgId, @Param("userId") Long userId, @Param("accountId") Long accountId);

    @Select(" SELECT " + COLUMNS + " FROM " + TABLE_NAME + " WHERE org_id=#{orgId} AND user_id=#{userId} AND account_type=#{accountType} AND account_index=#{accountIndex} AND type=#{type} AND create_for_user = 1")
    List<ApiKey> queryByUserIdAndType(@Param("orgId") Long orgId,
                                      @Param("userId") Long userId,
                                      @Param("accountType") Integer accountType,
                                      @Param("accountIndex") Integer accountIndex,
                                      @Param("type") Integer type);

    @Update(" UPDATE tb_api_key SET key_snow=#{keySnow}, secret_key=#{secretKey} WHERE id=#{id}")
    int refreshApiKey(ApiKey apiKey);

    @Update("update tb_api_key SET secret_key_seen_times_by_org = secret_key_seen_times_by_org + 1 where id = #{id} and org_id = #{orgId}")
    int incrOrgSeenTimes(@Param("id") Long id, @Param("orgId") Long orgId);

}
