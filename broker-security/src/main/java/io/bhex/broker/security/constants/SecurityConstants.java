/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security
 *@Date 2018/7/27
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.constants;

public class SecurityConstants {

    public static final String REQUEST_TIME = "_time";
    public static final String RANDOM_KEY = "_r";
    public static final String VERSION_KEY = "_v";
    public static final String PLATFORM_KEY = "_p";

    public static final String BIND_GA_KEY = "ga_key_";

    public static final Integer MOBILE_NOTICE_TYPE = 1;
    public static final Integer EMAIL_NOTICE_TYPE = 2;

    public static final Integer PRE_REQUEST_EFFECTIVE_MINUTES = 2 * 60;

}
