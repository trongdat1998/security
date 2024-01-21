/**********************************
 *@项目名称: broker-security
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/7/23
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import org.apache.ibatis.jdbc.SQL;

public class UserPwdChangeLogSqlProvider {

    private static final String TABLE_NAME = "tb_user_pwd_change_log";

    public String insert() {
        return new SQL() {
            {
                INSERT_INTO(TABLE_NAME);
                INTO_COLUMNS("id", "user_id", "change_type", "old_password", "old_snow", "new_password", "new_snow", "created");
                INTO_VALUES("#{id}", "#{userId}", "#{changeType}", "#{oldPassword}", "#{oldSnow}", "#{newPassword}", "#{newSnow}", "#{created}");
            }
        }.toString();
    }

}
