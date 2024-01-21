/**********************************
 *@项目名称: broker-parent
 *@文件名称: io.bhex.broker.mapper
 *@Date 2018/6/25
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import com.google.common.base.Strings;
import io.bhex.broker.security.service.entity.User;
import org.apache.ibatis.jdbc.SQL;

public class UserSqlProvider {

    private static final String TABLE_NAME = "tb_user";

    public String update(User user) {
        return new SQL() {
            {
                UPDATE("tb_user");
                if (!Strings.isNullOrEmpty(user.getPassword())) {
                    SET("password = #{password}");
                }
                if (!Strings.isNullOrEmpty(user.getSnow())) {
                    SET("snow = #{snow}");
                }
                if (!Strings.isNullOrEmpty(user.getTradePassword())) {
                    SET("trade_password = #{tradePassword}");
                }
                if (!Strings.isNullOrEmpty(user.getTradeSnow())) {
                    SET("trade_snow = #{tradeSnow}");
                }
                if (user.getGaKey() != null) {
                    SET("ga_key = #{gaKey}");
                }
                if (user.getUserStatus() != null) {
                    SET("user_status = #{userStatus}");
                }
                if (user.getApiLevel() != null) {
                    SET("api_level = #{apiLevel}");
                }
                SET("updated = #{updated}");
                WHERE("id = #{id}");
            }
        }.toString();
    }

}
