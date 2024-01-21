/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security
 *@Date 2018/10/19
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security;

import com.google.common.collect.Maps;
import com.google.gson.JsonObject;
import io.bhex.broker.common.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class NoticeRenderUtil {

    private static final Pattern PARAM_PLACEHOLDER_PATTERN = Pattern.compile("\\{([A-Za-z_$]+[A-Za-z_$\\d]*)\\}");

    public static String render(String content, Map<String, String> valueMap) {
        Matcher matcher = PARAM_PLACEHOLDER_PATTERN.matcher(content);
        while (matcher.find()) {
            String key = matcher.group();
            String keyName = key.substring(1, key.length() - 1).trim();
            content = content.replace(key, valueMap.getOrDefault(keyName, ""));
        }
        return content;
    }

    public static String render(String content, JsonObject valueJson) {
        Matcher matcher = PARAM_PLACEHOLDER_PATTERN.matcher(content);
        while (matcher.find()) {
            String key = matcher.group();
            String keyName = key.substring(1, key.length() - 1).trim();
            content = content.replace(key, JsonUtil.getString(valueJson, "." + keyName, ""));
        }
        return content;
    }

    public static void main(String[] args) {
        String content = "尊敬的用户：\n\t您的验证码是{code}，有效期{minutes}分钟，请勿告诉他人。";
        JsonObject dataJson = new JsonObject();
        dataJson.addProperty("code", "123456");
        dataJson.addProperty("minutes", "5");
        log.info(render(content, dataJson));
        Map<String, String> valueMap = Maps.newHashMap();
        valueMap.put("code", "123456");
        valueMap.put("minutes", "5");
        log.info(render(content, valueMap));
    }

}
