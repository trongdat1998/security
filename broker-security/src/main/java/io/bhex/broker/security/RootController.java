/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security
 *@Date 2018/8/10
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security;

import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;
import io.bhex.broker.common.exception.BrokerException;
import io.bhex.broker.common.util.JsonUtil;
import io.bhex.broker.grpc.common.Header;
import io.bhex.broker.grpc.security.ApiKeyInfo;
import io.bhex.broker.security.service.UserApiKeyService;
import io.bhex.broker.security.service.UserSecurityService;
import io.bhex.broker.security.service.entity.User;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

@Controller
@Slf4j
public class RootController {

    @Resource
    private UserSecurityService userSecurityService;

    @Resource
    private UserApiKeyService userApiKeyService;

    @Resource(name = "stringRedisTemplate")
    private StringRedisTemplate redisTemplate;

    @RequestMapping(value = "internal/metrics", produces = TextFormat.CONTENT_TYPE_004)
    @ResponseBody
    public String metrics(@RequestParam(name = "name[]", required = false) String[] names) throws IOException {
        Set<String> includedNameSet = names == null ? Collections.emptySet() : Sets.newHashSet(names);
        Writer writer = new StringWriter();
        TextFormat.write004(writer, CollectorRegistry.defaultRegistry.filteredMetricFamilySamples(includedNameSet));
        return writer.toString();
    }

//    @ResponseBody
//    @RequestMapping(value = "/internal/refresh_cache")
//    public String initBasicData() {
//        try {
//            userSecurityService.init();
//            return "OK";
//        } catch (Exception e) {
//            return "Error:" + Throwables.getStackTraceAsString(e);
//        }
//    }

    @ResponseBody
    @RequestMapping(value = "/internal/refresh_gakey")
    public String refreshGaKey(@RequestParam(name = "org_id") Long orgId,
                               @RequestParam(name = "user_id") Long userId) {
        try {
            userSecurityService.refreshUserGaKey(orgId, userId);
            return "OK";
        } catch (Exception e) {
            return "Error:" + Throwables.getStackTraceAsString(e);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/internal/refresh_user_cache")
    public String refreshUserCache(@RequestParam(name = "org_id") Long orgId,
                                   @RequestParam(name = "user_id") Long userId) {
        try {
            JsonObject dataObj = new JsonObject();
            User user = userSecurityService.refreshUserCache(orgId, userId);
            if (user != null) {
                dataObj.addProperty("orgId", orgId);
                dataObj.addProperty("userId", userId);
                dataObj.addProperty("status", user.getUserStatus());
                return JsonUtil.defaultGson().toJson(dataObj);
            }
            dataObj.addProperty("Error", "User Not found");
            return JsonUtil.defaultGson().toJson(dataObj);
        } catch (Exception e) {
            return "Error:" + Throwables.getStackTraceAsString(e);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/internal/get_user_cache")
    public String getUserCache(@RequestParam(name = "org_id") Long orgId,
                               @RequestParam(name = "user_id") Long userId) {
        try {
            return userSecurityService.getUserCache(orgId, userId);
        } catch (Exception e) {
            return "Error:" + Throwables.getStackTraceAsString(e);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/internal/reset_gakey")
    public String resetGaKey(@RequestParam(name = "org_id") Long orgId,
                             @RequestParam(name = "user_id") Long userId) {
        try {
            userSecurityService.resetUserGaKey(orgId, userId);
            return "OK";
        } catch (Exception e) {
            return "Error:" + Throwables.getStackTraceAsString(e);
        }
    }

    @ResponseBody
    @RequestMapping(value = "/internal/refresh_apikey")
    public String refreshApiKey(@RequestParam(name = "org_id") Long orgId,
                                @RequestParam(name = "user_id") Long userId) {
        try {
            userApiKeyService.refreshUserApiKey(orgId, userId);
            return "OK";
        } catch (Exception e) {
            return "Error:" + Throwables.getStackTraceAsString(e);
        }
    }

    @RequestMapping("/internal/api_key/create")
    @ResponseBody
    public String createReadOnlyApiKey(@RequestParam(name = "org_id") Long orgId,
                                       @RequestParam(name = "user_id") Long userId,
                                       @RequestParam(name = "accountType", required = false, defaultValue = "0") Integer accountType,
                                       @RequestParam(required = false, defaultValue = "0") Integer index,
                                       @RequestParam(name = "account_name", required = false, defaultValue = "") String accountName,
                                       @RequestParam(name = "account_id") Long accountId,
                                       @RequestParam(required = false, defaultValue = "read_only") String tag,
                                       @RequestParam Boolean createForUser) {
        try {
            Header header = Header.newBuilder().setOrgId(orgId).setUserId(userId).build();
            ApiKeyInfo apiKey = userApiKeyService.createReadOnlyApiKey(header, userId,
                    accountType, index, accountName, accountId, tag, createForUser).getApiKey();
            return JsonUtil.defaultGson().toJson(apiKey);
        } catch (BrokerException e) {
            return e.getMessage();
        } catch (Exception e) {
            log.error("create read only api key error", e);
            return Throwables.getStackTraceAsString(e);
        }
    }

    @RequestMapping("/internal/org_api_key/create")
    @ResponseBody
    public String createOrgApi(@RequestParam(name = "org_id") Long orgId,
                               @RequestParam(required = false, defaultValue = "read_only") String tag,
                               @RequestParam Boolean createForUser) {
        try {
            Header header = Header.newBuilder().setOrgId(orgId).setUserId(0L).build();
            ApiKeyInfo apiKey = userApiKeyService.createOrgApiKey(header, tag, createForUser).getApiKey();
            return JsonUtil.defaultGson().toJson(apiKey);
        } catch (BrokerException e) {
            return e.getMessage();
        } catch (Exception e) {
            log.error("create read only api key error", e);
            return Throwables.getStackTraceAsString(e);
        }
    }

    @Deprecated
    @RequestMapping("/internal/org_api_key/merge")
    @ResponseBody
    public String mergeOrgApi(@RequestParam(name = "org_id") Long orgId,
                              @RequestParam(required = false, defaultValue = "create by system") String tag,
                              @RequestParam(name = "access_key", required = false, defaultValue = "") String accessKey,
                              @RequestParam(name = "secret_key", required = false, defaultValue = "") String secretKey) {
        try {
            userApiKeyService.mergeExistedOrgApiKey(orgId, tag, accessKey, secretKey);
            return "Success";
        } catch (BrokerException e) {
            return e.getMessage();
        } catch (Exception e) {
            log.error("create read only api key error", e);
            return Throwables.getStackTraceAsString(e);
        }
    }

    @RequestMapping("/internal/update_api_level")
    @ResponseBody
    public String updateUserApiLevel(@RequestParam(name = "org_id") Long orgId,
                                     @RequestParam(name = "user_id") Long userId,
                                     @RequestParam(name = "api_level") Integer apiLevel) {
        try {
            if (apiLevel == null || apiLevel > 6 || apiLevel < 0) {
                return "Wrong apiLevel";
            }
            Boolean result = userSecurityService.updateApiLevel(orgId, userId, apiLevel);
            return "Success:" + result;
        } catch (BrokerException e) {
            return e.getMessage();
        } catch (Exception e) {
            log.error("update user api level error", e);
            return Throwables.getStackTraceAsString(e);
        }
    }

//    @ResponseBody
//    @RequestMapping(value = "/security/internal/get_code", produces = {MediaType.APPLICATION_JSON_UTF8_VALUE})
//    public String getVerifyCode(@RequestParam Long id) {
//        JsonObject jsonObject = new JsonObject();
//        VerifyCode verifyCode = internalService.getVerifyCode(id);
//        if (verifyCode != null) {
//            jsonObject.addProperty("code", verifyCode.getCode());
//            jsonObject.addProperty("content", verifyCode.getContent());
//        } else {
//            jsonObject.addProperty("code", "0");
//            jsonObject.addProperty("content", "This is a error request");
//        }
//        return JsonUtil.defaultGson().toJson(jsonObject);
//    }
//
//    @ResponseBody
//    @RequestMapping(value = "security/internal/query_code", produces = {MediaType.APPLICATION_JSON_UTF8_VALUE})
//    public String queryVerifyCode(@RequestParam String receiver) {
//        return JsonUtil.defaultGson().toJson(internalService.queryVerifyCode(receiver));
//    }

    @RequestMapping(value = "/internal/redis/set")
    @ResponseBody
    public String internalRedisSetOperation(String key, String value) {
        if (!Strings.isNullOrEmpty(key) && !Strings.isNullOrEmpty(value)) {
            log.info("redisOperation: set {} {}", key, value);
            redisTemplate.opsForValue().set(key, value);
            return "OK";
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/hset")
    @ResponseBody
    public String internalRedisHSetOperation(String key, String field, String value) {
        if (Stream.of(key, field, value).noneMatch(Strings::isNullOrEmpty)) {
            log.info("redisOperation: hset {} {} {}", key, field, value);
            redisTemplate.opsForHash().put(key, field, value);
            return "OK";
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/del")
    @ResponseBody
    public String internalRedisDelOperation(String key) {
        if (!Strings.isNullOrEmpty(key)) {
            log.info("redisOperation: del {}", key);
            redisTemplate.delete(key);
            return "OK";
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/hdel")
    @ResponseBody
    public String internalRedisHDelOperation(String key, String field) {
        if (Stream.of(key, field).noneMatch(Strings::isNullOrEmpty)) {
            log.info("redisOperation: hdel {} {}", key, field);
            redisTemplate.opsForHash().delete(key, field);
            return "OK";
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/get")
    @ResponseBody
    public String internalRedisGetOperation(String key) {
        if (!Strings.isNullOrEmpty(key)) {
            log.info("redisOperation: get {}", key);
            String value = redisTemplate.opsForValue().get(key);
            return Strings.nullToEmpty(value);
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/hget")
    @ResponseBody
    public String internalRedisHGetOperation(String key, String field) {
        if (Stream.of(key, field).noneMatch(Strings::isNullOrEmpty)) {
            log.info("redisOperation: hget {} {}", key, field);
            Object value = redisTemplate.opsForHash().get(key, field);
            return value == null ? "" : value.toString();
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/hgetall")
    @ResponseBody
    public String internalRedisHGetAllOperation(String key) {
        if (!Strings.isNullOrEmpty(key)) {
            log.info("redisOperation: hgetall {}", key);
            Map<Object, Object> valuesMap = redisTemplate.opsForHash().entries(key);
            return JsonUtil.defaultGson().toJson(valuesMap);
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/sadd")
    @ResponseBody
    public String internalRedisSAddOperation(String key, String values) {
        if (!Strings.isNullOrEmpty(key) && !Strings.isNullOrEmpty(values)) {
            log.info("redisOperation: sadd {}", key);
            return "" + redisTemplate.opsForSet().add(key, values.split(","));
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/smembers")
    @ResponseBody
    public String internalRedisSMembersOperation(String key) {
        if (!Strings.isNullOrEmpty(key)) {
            log.info("redisOperation: members {}", key);
            return JsonUtil.defaultGson().toJson(redisTemplate.opsForSet().members(key));
        } else {
            return "error: check param";
        }
    }

    @RequestMapping(value = "/internal/redis/srem")
    @ResponseBody
    public String internalRedisSRemoveOperation(String key, String value) {
        if (!Strings.isNullOrEmpty(key) && !Strings.isNullOrEmpty(value)) {
            log.info("redisOperation: members {}", key);
            return "" + redisTemplate.opsForSet().remove(key, value);
        } else {
            return "error: check param";
        }
    }

}
