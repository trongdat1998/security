/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/8/6
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import com.google.common.base.Strings;
import io.bhex.broker.security.service.entity.ApiKey;
import org.apache.ibatis.jdbc.SQL;

public class ApiKeySqlProvider {

    private static final String TABLE_NAME = "tb_api_key";
    private static final String LOG_TABLE_NAME = "tb_api_key_log";

    public String insertApiKey(ApiKey apiKey) {
        return insert(apiKey, false);
    }

    public String insertApiKeyLog(ApiKey apiKey) {
        return insert(apiKey, true);
    }

    private String insert(ApiKey apiKey, Boolean isLog) {
        return new SQL() {
            {
                INSERT_INTO(!isLog ? TABLE_NAME : LOG_TABLE_NAME);
                VALUES("org_id", "#{orgId}");
                VALUES("user_id", "#{userId}");
                VALUES("account_id", "#{accountId}");
                if (apiKey.getAccountType() != null) {
                    VALUES("account_type", "#{accountType}");
                }
                if (apiKey.getAccountIndex() != null) {
                    VALUES("account_index", "#{accountIndex}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getAccountName())) {
                    VALUES("account_name", "#{accountName}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getApiKey())) {
                    VALUES("api_key", "#{apiKey}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getSecretKey())) {
                    VALUES("secret_key", "#{secretKey}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getKeySnow())) {
                    VALUES("key_snow", "#{keySnow}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getTag())) {
                    VALUES("tag", "#{tag}");
                }
                if (!Strings.isNullOrEmpty(apiKey.getIpWhiteList())) {
                    VALUES("ip_white_list", "#{ipWhiteList}");
                }
                if (apiKey.getType() != null) {
                    VALUES("type", "#{type}");
                }
                if (apiKey.getLevel() != null) {
                    VALUES("level", "#{level}");
                }
                if (apiKey.getCreateForUser() != null) {
                    VALUES("create_for_user", "#{createForUser}");
                }
                if (apiKey.getStatus() != null) {
                    VALUES("status", "#{status}");
                }
                VALUES("created", "#{created}");
                VALUES("updated", "#{updated}");
            }
        }.toString();
    }

    public String update(ApiKey apiKey) {
        return new SQL() {
            {
                UPDATE(TABLE_NAME);
                if (apiKey.getTag() != null) {
                    SET("tag = #{tag}");
                }
                if (apiKey.getIpWhiteList() != null) {
                    SET("ip_white_list = #{ipWhiteList}");
                }
                if (apiKey.getLevel() != null) {
                    SET("level = #{level}");
                }
                if (apiKey.getStatus() != null) {
                    SET("status = #{status}");
                }
                SET("updated = #{updated}");
                WHERE("id = #{id}");
            }
        }.toString();
    }

}
