/**********************************
 *@项目名称: security
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/8/6
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.hash.Hashing;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.Resource;

import io.bhex.broker.common.exception.BrokerErrorCode;
import io.bhex.broker.common.exception.BrokerException;
import io.bhex.broker.common.util.CryptoUtil;
import io.bhex.broker.common.util.JsonUtil;
import io.bhex.broker.grpc.common.AccountTypeEnum;
import io.bhex.broker.grpc.common.Header;
import io.bhex.broker.grpc.security.ApiKeyInfo;
import io.bhex.broker.grpc.security.ApiKeyStatus;
import io.bhex.broker.grpc.security.ChangeUserApiLevelResponse;
import io.bhex.broker.grpc.security.SecurityCreateApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityDeleteApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityGetApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityQueryUserApiKeysResponse;
import io.bhex.broker.grpc.security.SecurityUpdateApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityUpdateApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityValidApiAccessResponse;
import io.bhex.broker.grpc.security.SecurityValidApiKeyResponse;
import io.bhex.broker.security.domain.AccountType;
import io.bhex.broker.security.service.entity.ApiKey;
import io.bhex.broker.security.service.entity.User;
import io.bhex.broker.security.uitl.SignUtil;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserApiKeyService {

    private static final int API_KEY_TYPE_READ_ONLY = 0;
    private static final int API_KEY_TYPE_TRADABLE = 1;

    private static final int API_KEY_TYPE_ORG_API_READONLY = 10; // org_api，只读 api key
    private static final int API_KEY_TYPE_ORG_API = 11; // org_api，可执行其他操作的 api key

    private static final Long USER_CACHE_SECOND = 30 * 60L;

    private static final int API_KEY_LEVEL_L1 = 1;

    private static final int API_KEY_LEVEL_L3 = 3;

    private static final int API_KEY_CACHE_INVALID_SECONDS = 30 * 60;
    private static final int SECRET_KEY_CACHE_INVALID_SECONDS = 10 * 60;
    private static final TimeUnit API_KEY_CACHE_INVALID_TIME_UNIT = TimeUnit.SECONDS;

    private static final String NULL_API_KEY_STR = "{}";

    private static final int API_KEY_LENGTH = 64;

    private LoadingCache<String, String> secretKeyCache = CacheBuilder.newBuilder()
            .expireAfterAccess(SECRET_KEY_CACHE_INVALID_SECONDS, API_KEY_CACHE_INVALID_TIME_UNIT)
            .build(new CacheLoader<String, String>() {
                @Override
                public String load(String accessKey) throws Exception {
                    ApiKey apiKey = apiKeyMapper.getByApiKey(accessKey);
                    if (apiKey == null) {
                        return "";
                    }
                    if (Strings.isNullOrEmpty(apiKey.getKeySnow())) {
                        return apiKey.getSecretKey();
                    } else {
                        return SignUtil.decryptData(getKey(accessKey, apiKey.getKeySnow()), apiKey.getSecretKey());
                    }
                }
            });

    @Resource
    private ApiKeyMapper apiKeyMapper;

    @Resource(name = "stringRedisTemplate")
    private StringRedisTemplate redisTemplate;

    @Resource
    private UserSecurityService userSecurityService;

    @Resource
    private UserMapper userMapper;

    // 目前只读ApiKey都是手工创建，可以创建多个
    public SecurityCreateApiKeyResponse createReadOnlyApiKey(Header header, Long userId,
                                                             Integer accountType, Integer accountIndex, String accountName, Long accountId,
                                                             String tag, boolean createForUser) throws Exception {
        return createApiKey(header, userId, AccountType.fromValue(accountType).toAccountTypeEnum(), accountIndex, accountName, accountId, tag, API_KEY_TYPE_READ_ONLY, createForUser);
    }

    public SecurityCreateApiKeyResponse createOrgApiKey(Header header, String tag, boolean createForUser) throws Exception {
        return createApiKey(header, 0L, AccountTypeEnum.COIN, 0, "", 0L, tag, API_KEY_TYPE_ORG_API, createForUser);
    }

    // 目前只允许用户创建一对ApiKey
    public SecurityCreateApiKeyResponse createApiKey(Header header, Long userId,
                                                     AccountTypeEnum accountTypeEnum, Integer accountIndex, String accountName, Long accountId,
                                                     String tag, int type, boolean createForUser) throws Exception {
//        if (type != API_KEY_TYPE_TRADABLE && type != API_KEY_TYPE_READ_ONLY && type != API_KEY_TYPE_ORG_API && type != API_KEY_TYPE_ORG_API_READONLY) {
//            return SecurityCreateApiKeyResponse.newBuilder().setRet(BrokerErrorCode.PARAM_INVALID.code()).build();
//        }
        if (Stream.of(API_KEY_TYPE_TRADABLE, API_KEY_TYPE_READ_ONLY, API_KEY_TYPE_ORG_API, API_KEY_TYPE_ORG_API_READONLY).noneMatch(requiredType -> requiredType == type)) {
            return SecurityCreateApiKeyResponse.newBuilder().setRet(BrokerErrorCode.PARAM_INVALID.code()).build();
        }

        int maxRecord = type < 10 ? 5 : 2; // 目前给予 OrgApi 每个券商 + type两对Key, 每个用户 + type 1对
        if (createForUser) {
            // 现在暂时不允许用户手动创建多个非只读Key
            if (apiKeyMapper.queryByUserIdAndType(header.getOrgId(), userId, AccountType.fromAccountTypeEnum(accountTypeEnum).value(), accountIndex, type).size() >= maxRecord) {
                return SecurityCreateApiKeyResponse.newBuilder().setRet(BrokerErrorCode.CREATE_API_KEY_EXCEED_LIMIT.code()).build();
            }
        }

        ApiKey apiKey = createApiKey(header.getOrgId(), userId, accountTypeEnum, accountIndex, accountName, accountId, tag, type, createForUser);
        ApiKeyInfo apiKeyInfo = getApiKeyInfo(apiKey).toBuilder()
                .setSecretKey(SignUtil.decryptData(getKey(apiKey.getApiKey(), apiKey.getKeySnow()), apiKey.getSecretKey())).build();
        return SecurityCreateApiKeyResponse.newBuilder().setApiKey(apiKeyInfo).build();
    }

    // 目前创建的API都是直接启用的，所以创建时直接执行状态为启用
    // 等级暂时都定为L1
    private ApiKey createApiKey(Long orgId, Long userId,
                                AccountTypeEnum accountTypeEnum, Integer accountIndex, String accountName, Long accountId,
                                String tag, int type, boolean createForUser) throws Exception {
        Long timestamp = System.currentTimeMillis();
        String accessKey = CryptoUtil.getRandomCode(64);
        String secretKey = CryptoUtil.getRandomCode(64);
        String keySnow = CryptoUtil.getRandomCode(16);

        ApiKey apiKey = ApiKey.builder()
                .orgId(orgId)
                .userId(userId)
                .accountType(AccountType.fromAccountTypeEnum(accountTypeEnum).value())
                .accountIndex(accountIndex)
                .accountName(accountName)
                .accountId(accountId)
                .apiKey(accessKey)
                .secretKey(SignUtil.encryptData(getKey(accessKey, keySnow), secretKey))
                .keySnow(keySnow)
                .tag(tag)
                .type(type)
                .level(API_KEY_LEVEL_L1)
                .specialPermission(0)
                .createForUser(createForUser ? 1 : 0)
                .status(ApiKeyStatus.ENABLE_VALUE)
                .created(timestamp)
                .updated(timestamp)
                .build();
        apiKeyMapper.insert(apiKey);
        return apiKey;
    }

    @Deprecated
    public void mergeExistedOrgApiKey(Long orgId, String tag, String accessKey, String secretKey) throws Exception {
        Long timestamp = System.currentTimeMillis();
        String keySnow = CryptoUtil.getRandomCode(16);

        ApiKey apiKey = ApiKey.builder()
                .orgId(orgId)
                .userId(0L)
                .accountId(0L)
                .apiKey(accessKey)
                .secretKey(SignUtil.encryptData(getKey(accessKey, keySnow), secretKey))
                .keySnow(keySnow)
                .tag(tag)
                .type(API_KEY_TYPE_ORG_API)
                .level(API_KEY_LEVEL_L1)
                .specialPermission(0)
                .status(ApiKeyStatus.ENABLE_VALUE)
                .created(timestamp)
                .updated(timestamp)
                .build();
        apiKeyMapper.insert(apiKey);
    }

    @Transactional(propagation = Propagation.REQUIRED, isolation = Isolation.READ_COMMITTED)
    public SecurityUpdateApiKeyResponse updateApiKey(Header header, Long userId, Long id,
                                                     String ipWhiteList, Integer status, Integer updateValue) {
        ApiKey apiKey = apiKeyMapper.getUserApiKeyById(id, header.getOrgId(), userId);
        if (apiKey == null) {
            log.warn("update apiKey, cannot find ApiKey record by apiKeyId:{}", id);
            throw new BrokerException(BrokerErrorCode.REQUEST_INVALID);
        }
//        if (apiKey.getType() == API_KEY_TYPE_READ_ONLY) {
//            log.warn("update a read only api_key, warning!!!");
//            throw new BrokerException(BrokerErrorCode.REQUEST_INVALID);
//        }
        ApiKey updateObj = ApiKey.builder().id(id).updated(System.currentTimeMillis()).build();
        if (updateValue == SecurityUpdateApiKeyRequest.UpdateType.UPDATE_IP_WHITE_LIST_VALUE) {
            updateObj.setIpWhiteList(ipWhiteList);
        } else if (updateValue == SecurityUpdateApiKeyRequest.UpdateType.UPDATE_STATUS_VALUE) {
            if (status != 0 && ApiKeyStatus.forNumber(status) != null) {
                updateObj.setStatus(status);
            }
        }
        apiKeyMapper.update(updateObj);
        apiKey = apiKeyMapper.getById(id);

        redisTemplate.delete(apiKey.getApiKey());
        secretKeyCache.invalidate(apiKey.getApiKey());

        return SecurityUpdateApiKeyResponse.newBuilder().setApiKey(getApiKeyInfo(apiKey)).build();
    }

    public SecurityDeleteApiKeyResponse deleteApiKey(Header header, Long userId, Long id) {
        ApiKey apiKey = apiKeyMapper.getUserApiKeyById(id, header.getOrgId(), userId);
        if (apiKey == null) {
            log.warn("delete apiKey, cannot find ApiKey record by apiKeyId:{}, return true", id);
            return SecurityDeleteApiKeyResponse.newBuilder().build();
        }
//        if (apiKey.getType() == API_KEY_TYPE_READ_ONLY) {
//            log.warn("delete a read only api_key, warning!!!");
//            throw new BrokerException(BrokerErrorCode.REQUEST_INVALID);
//        }
        apiKeyMapper.insertLog(apiKey);
        apiKeyMapper.delete(id);

        redisTemplate.delete(apiKey.getApiKey());
        secretKeyCache.invalidate(apiKey.getApiKey());
        return SecurityDeleteApiKeyResponse.newBuilder().build();
    }

    /**
     * 获取单个api的详情
     *
     * @param header
     * @param userId
     * @param id
     * @return
     */
    public SecurityGetApiKeyResponse getApiKey(Header header, Long userId, Long id) {
        ApiKey apiKey = apiKeyMapper.getUserApiKeyById(id, header.getOrgId(), userId);
        if (apiKey != null) {
            return SecurityGetApiKeyResponse.newBuilder().setApiKey(getApiKeyInfo(apiKey)).build();
        }
        return SecurityGetApiKeyResponse.newBuilder().build();
    }

    /**
     * 获取api_key列表
     *
     * @param header
     * @param userId
     * @return
     */
    public SecurityQueryUserApiKeysResponse queryUserApiKeys(Header header, Long userId) {
        int level = 0;
        if (userId > 0) {
            User user = userSecurityService.getCacheUser(header.getOrgId(), userId);
            level = user.getApiLevel();
        }
        final int resultLevel = level;
        List<ApiKey> apiKeyList = apiKeyMapper.queryByUserId(header.getOrgId(), userId);
        return SecurityQueryUserApiKeysResponse.newBuilder()
                .addAllApiKey(apiKeyList.stream()
//                        // 加载所有api，不在区分是可操作还是只读
//                        .filter(apiKey -> apiKey.getType() == API_KEY_TYPE_TRADABLE)
//                        .filter(apiKey -> apiKey.getType() != API_KEY_TYPE_READ_ONLY)
                        .map(this::getApiKeyInfo).map(apiKeyInfo -> apiKeyInfo.toBuilder().setLevel(resultLevel).build()).collect(Collectors.toList())).build();
    }

    public SecurityQueryUserApiKeysResponse queryUserApiKeysByAccountId(Header header, Long userId, Long accuontId) {
        List<ApiKey> apiKeyList = apiKeyMapper.queryByAccountId(header.getOrgId(), userId, accuontId);
        SecurityQueryUserApiKeysResponse response = SecurityQueryUserApiKeysResponse.newBuilder()
                .addAllApiKey(apiKeyList.stream()
                        .map(k -> getApiKeyInfo(k, true))
                        .collect(Collectors.toList())).build();
        apiKeyList.forEach(apiKey -> {
            if (apiKey.getSecretKeySeenTimesByOrg() == 0) {
                apiKeyMapper.incrOrgSeenTimes(apiKey.getId(), apiKey.getOrgId());
            }
        });
        return response;
    }

    /**
     * 做市账户添加默认level = 3
     *
     * @param orgId
     * @param userId
     * @return
     */
    public ChangeUserApiLevelResponse changeUserApiLevel(long orgId, long userId, int level) {
        log.info("changeUserApiLevel orgId {} userId {} level {}", orgId, userId, level);
        User user = userMapper.getByUserId(orgId, userId);
        if (user == null) {
            throw new BrokerException(BrokerErrorCode.USER_NOT_EXIST);
        }
        if (user.getApiLevel() == level) {
            return ChangeUserApiLevelResponse.newBuilder().setRet(1).build();
        }
        if (user.getApiLevel() > level) {
            return ChangeUserApiLevelResponse.newBuilder().setRet(1).build();
        }
        User updateObj = User.builder()
                .id(user.getId())
                .apiLevel(level)
                .updated(System.currentTimeMillis())
                .build();
        userMapper.update(updateObj);
        try {
            redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(userMapper.getByUserId(orgId, userId)), USER_CACHE_SECOND, TimeUnit.SECONDS);
        } catch (Exception e) {
            return ChangeUserApiLevelResponse.newBuilder().setRet(0).build();
        }
        return JsonUtil.defaultGson().fromJson(redisTemplate.opsForValue().get(user.getCacheKey()), User.class).getApiLevel() == level
                ? ChangeUserApiLevelResponse.newBuilder().setRet(1).build() : ChangeUserApiLevelResponse.newBuilder().setRet(0).build();
    }

    public SecurityValidApiAccessResponse validApiRequest(Header header, String originStr, String mbxApiKey, String signature,
                                                          boolean isOrgApiRequest, boolean forceCheckIpWhiteList) throws Exception {
        ApiKey cachedApiKey = this.getApiKey(mbxApiKey);
        if (cachedApiKey == null || !cachedApiKey.getOrgId().equals(header.getOrgId())) {
            log.warn(" validApiRequest cannot find api_key record with orgId:{}, access_key:{}, originStr:{}, signature:{}",
                    header.getOrgId(), mbxApiKey, originStr, signature);
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (cachedApiKey.getStatus() != ApiKeyStatus.ENABLE_VALUE) {
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.API_KEY_NOT_ENABLE.code()).build();
        }
        if (!isOrgApiRequest && cachedApiKey.getType() >= 10 || (isOrgApiRequest && cachedApiKey.getType() < 10)) {
            log.warn(" validApiRequest request type:{} cannot match orgId:{}, requestPlatform:{}, access_key:{}, originStr:{}, signature:{}",
                    cachedApiKey.getType(), header.getOrgId(), header.getPlatform(), mbxApiKey, originStr, signature);
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }

        String secretKey = secretKeyCache.get(mbxApiKey);
        if (!Hashing.hmacSha256(secretKey.getBytes()).hashString(originStr, Charsets.UTF_8).toString().equals(signature)) {
            log.warn("request with orgId:{}, access_key:{}, originStr:{} signature cannot match. {} != {}",
                    header.getOrgId(), mbxApiKey, originStr, signature, Hashing.hmacSha256(secretKey.getBytes()).hashString(originStr, Charsets.UTF_8).toString());
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (forceCheckIpWhiteList && Strings.isNullOrEmpty(cachedApiKey.getIpWhiteList())) {
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.BIND_IP_WHITE_LIST_FIRST.code()).build();
        }
        if (!Strings.isNullOrEmpty(cachedApiKey.getIpWhiteList()) && !cachedApiKey.getIpWhiteList().contains(header.getRemoteIp())) {
            return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.IP_NOT_IN_WHITELIST.code()).build();
        }

        // type > 10的是OrgApi
        int apiLevel = 0;
        if (cachedApiKey.getType() < 10) {
            User user = userSecurityService.getCacheUser(header.getOrgId(), cachedApiKey.getUserId());
            if (user == null) {
                log.error(" validApiRequest orgId:{}, access_key:{}, originStr:{}, signature:{} cannot find user:{}",
                        header.getOrgId(), mbxApiKey, originStr, signature, cachedApiKey.getUserId());
                return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
            }
            if (user.getUserStatus() != 1) {
                log.warn("user:{} status is disable. return apiKey is disable", cachedApiKey.getUserId());
                return SecurityValidApiAccessResponse.newBuilder().setRet(BrokerErrorCode.API_KEY_NOT_ENABLE.code()).build();
            }
            apiLevel = user.getApiLevel() == null ? 2 : user.getApiLevel();
        }
        return SecurityValidApiAccessResponse.newBuilder()
                .setUserId(cachedApiKey.getUserId())
                .setAccountId(cachedApiKey.getAccountId())
                .setType(cachedApiKey.getType() == null ? API_KEY_TYPE_TRADABLE : cachedApiKey.getType())
                .setLevel(apiLevel)
                .setAccountType(AccountType.fromValue(cachedApiKey.getAccountType()).toAccountTypeEnum())
                .setAccountIndex(cachedApiKey.getAccountIndex())
                .setSpecialPermission(cachedApiKey.getSpecialPermission())
                .build();
    }

    @Deprecated
    public SecurityValidApiKeyResponse validApiKey(Header header, String apiKey) throws Exception {
        ApiKey key = this.getApiKey(apiKey);
        if (key == null) {
            log.warn("cannot find ApiKey record by apiKey:{}", apiKey);
            return SecurityValidApiKeyResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (key.getStatus() != ApiKeyStatus.ENABLE_VALUE) {
            return SecurityValidApiKeyResponse.newBuilder().setRet(BrokerErrorCode.API_KEY_NOT_ENABLE.code()).build();
        }
        User user = userSecurityService.getCacheUser(header.getOrgId(), key.getUserId());
        if (user == null) {
            return SecurityValidApiKeyResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (user.getUserStatus() != 1) {
            log.info("user:{} status is disable. return apiKey is disable", key.getUserId());
            return SecurityValidApiKeyResponse.newBuilder().setRet(BrokerErrorCode.API_KEY_NOT_ENABLE.code()).build();
        }
        return SecurityValidApiKeyResponse.newBuilder()
                .setUserId(key.getUserId())
                .setAccountId(key.getAccountId())
                .setType(key.getType() == null ? API_KEY_TYPE_TRADABLE : key.getType())
                .setLevel(key.getLevel() == null ? 0 : key.getLevel())
                .build();
    }

    public ApiKey getApiKey(String apiKey) throws Exception {
        if (Strings.isNullOrEmpty(apiKey) || apiKey.length() < API_KEY_LENGTH) {
            return null;
        }
        String apiKeyStr = redisTemplate.opsForValue().get(apiKey);
        ApiKey cachedApiKey;
        if (!Strings.isNullOrEmpty(apiKeyStr)) {
            if (apiKeyStr.equals(NULL_API_KEY_STR)) {
                return null;
            }
            cachedApiKey = JsonUtil.defaultGson().fromJson(apiKeyStr, ApiKey.class);
        } else {
            cachedApiKey = apiKeyMapper.getByApiKey(apiKey);
            if (cachedApiKey == null) {
                redisTemplate.opsForValue().set(apiKey, NULL_API_KEY_STR, API_KEY_CACHE_INVALID_SECONDS, API_KEY_CACHE_INVALID_TIME_UNIT);
                return null;
            } else {
                String secretKey = cachedApiKey.getSecretKey();
                cachedApiKey.setSecretKey("");
                redisTemplate.opsForValue().set(apiKey, JsonUtil.defaultGson().toJson(cachedApiKey),
                        API_KEY_CACHE_INVALID_SECONDS, API_KEY_CACHE_INVALID_TIME_UNIT);
                if (Strings.isNullOrEmpty(cachedApiKey.getKeySnow())) {
                    secretKeyCache.put(apiKey, secretKey);
                } else {
                    secretKeyCache.put(apiKey, SignUtil.decryptData(getKey(cachedApiKey.getApiKey(), cachedApiKey.getKeySnow()), secretKey));
                }
            }
        }
        if (Strings.isNullOrEmpty(cachedApiKey.getApiKey())) {
            return null;
        }
        return cachedApiKey;
    }

    private ApiKeyInfo getApiKeyInfo(ApiKey apiKey, boolean withSecretKey) {

        ApiKeyInfo.Builder builder = ApiKeyInfo.newBuilder()
                .setId(apiKey.getId() == null ? 0 : apiKey.getId())
                .setUserId(apiKey.getUserId())
                .setAccountType(AccountType.fromValue(apiKey.getAccountType()).toAccountTypeEnum())
                .setIndex(apiKey.getAccountIndex())
                .setAccountName(apiKey.getAccountName())
                .setAccountId(apiKey.getAccountId())
                .setApiKey(apiKey.getApiKey())
                .setTag(apiKey.getTag())
                .setIpWhiteList(Strings.nullToEmpty(apiKey.getIpWhiteList()))
                .setType(apiKey.getType() == null ? API_KEY_TYPE_TRADABLE : apiKey.getType())
                .setLevel(apiKey.getLevel() == null ? 1 : apiKey.getLevel())
                .setStatus(ApiKeyStatus.forNumber(apiKey.getStatus()))
                .setCreated(apiKey.getCreated())
                .setUpdated(apiKey.getUpdated())
                .setSecretKey("");
        try {
            if (withSecretKey && apiKey.getSecretKeySeenTimesByOrg() == 0) {
                String secretKey = SignUtil.decryptData(getKey(apiKey.getApiKey(), apiKey.getKeySnow()), apiKey.getSecretKey());
                builder.setSecretKey(secretKey);
            }
        } catch (Exception e) {
            log.error("decrypt secret key error", e);
        }

        return builder.build();

    }

    private ApiKeyInfo getApiKeyInfo(ApiKey apiKey) {
        return getApiKeyInfo(apiKey, false);
    }

    private String getKey(String apiKey, String keySnow) {
        return apiKey.substring(5, 31) + keySnow;
    }

    public void refreshUserApiKey(Long orgId, Long userId) {
        try {
            List<ApiKey> apiKeyList = apiKeyMapper.queryByUserId(orgId, userId);
            for (ApiKey apiKey : apiKeyList) {
                if (Strings.isNullOrEmpty(apiKey.getKeySnow())) {
                    String keySnow = CryptoUtil.getRandomCode(16);
                    String secretKey = SignUtil.encryptData(getKey(apiKey.getApiKey(), keySnow), apiKey.getSecretKey());
                    ApiKey updateObj = ApiKey.builder()
                            .id(apiKey.getId())
                            .keySnow(keySnow)
                            .secretKey(secretKey)
                            .build();
                    apiKeyMapper.refreshApiKey(updateObj);
                }
                redisTemplate.delete(apiKey.getApiKey());
                secretKeyCache.invalidate(apiKey.getApiKey());
            }
        } catch (Exception e) {
            log.error("refresh user apiKey error");
        }
    }

}
