/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/7/26
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.hash.Hashing;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import io.bhex.base.common.CodeFeedbackRequest;
import io.bhex.base.common.SimpleMailRequest;
import io.bhex.base.common.SimpleSMSRequest;
import io.bhex.base.common.Telephone;
import io.bhex.base.idgen.api.ISequenceGenerator;
import io.bhex.broker.common.exception.BrokerErrorCode;
import io.bhex.broker.common.util.CryptoUtil;
import io.bhex.broker.common.util.JsonUtil;
import io.bhex.broker.grpc.common.Header;
import io.bhex.broker.grpc.common.Platform;
import io.bhex.broker.grpc.security.*;
import io.bhex.broker.security.SecurityProperties;
import io.bhex.broker.security.constants.SecurityConstants;
import io.bhex.broker.security.grpc.client.GrpcCodeFeedbackService;
import io.bhex.broker.security.grpc.client.GrpcEmailService;
import io.bhex.broker.security.grpc.client.GrpcSmsService;
import io.bhex.broker.security.service.entity.User;
import io.bhex.broker.security.service.entity.UserBindGACheck;
import io.bhex.broker.security.service.entity.UserPwdChangeLog;
import io.bhex.broker.security.service.entity.VerifyCode;
import io.bhex.broker.security.uitl.SignUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import javax.annotation.Resource;
import javax.crypto.BadPaddingException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class UserSecurityService {

    private static final String ENV_KEY = "ENCRYPT_TOKEN_PASSWORD";
    /**
     * Encrypt password for token
     */
    private static final String TOKEN_ENCRYPT_PASSWORD = System.getenv(ENV_KEY);

    private static final String VERIFY_CODE_KEY = "%s_%s_%s_%s_%s";

    private static final int USER_ENABLE_STATUS = 1;

    private static final String APP_SECURITY_TOKEN_VERSION = "1.1";

    @Resource
    private UserMapper userMapper;

    @Resource
    private UserPwdChangeLogMapper userPwdChangeLogMapper;

    @Resource
    private SecurityProperties securityProperties;

    @Resource(name = "stringRedisTemplate")
    private StringRedisTemplate redisTemplate;

    @Resource
    private ISequenceGenerator sequenceGenerator;

    @Resource
    private GrpcSmsService grpcSmsService;

    @Resource
    private GrpcEmailService grpcEmailService;

    @Resource
    private VerifyCodeMapper verifyCodeMapper;

    @Resource
    private GrpcCodeFeedbackService grpcCodeFeedbackService;
//    @Value("${security.skipSendVerifyCode:false}")
//    private Boolean skipSendVerifyCode;

    @Resource
    private UserApiKeyService userApiKeyService;

    private static final Long USER_CACHE_SECOND = 30 * 60L;

    @Value("${verify-captcha:true}")
    private Boolean verifyCaptcha;

    @Value("${global-notify-type:1}")
    private Integer globalNotifyType;

//    private LoadingCache<String, User> USER_CACHE = CacheBuilder.newBuilder()
//            .expireAfterAccess(USER_CACHE_SECOND, TimeUnit.SECONDS)
//            .build(new CacheLoader<String, User>() {
//                @Override
//                public User load(String cacheKey) throws Exception {
//                    Long orgId = Longs.tryParse(cacheKey.split("-")[0]);
//                    Long userId = Longs.tryParse(cacheKey.split("-")[1]);
//                    return userMapper.getByUserId(orgId, userId);
//                }
//            });

    public SecurityRegisterResponse register(Header header, Long userId, String password) {
        String snow = CryptoUtil.getRandomCode(8);
        Long timestamp = System.currentTimeMillis();
        User user = User.builder()
                .orgId(header.getOrgId())
                .userId(userId)
                .password(CryptoUtil.encryptPassword(password, snow))
                .snow(snow)
                .ip(header.getRemoteIp())
                .userStatus(1)
                .apiLevel(2)
                .created(timestamp)
                .updated(timestamp)
                .build();
        userMapper.insert(user);
        try {
            redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(user), USER_CACHE_SECOND, TimeUnit.SECONDS);
        } catch (Exception e) {
            // ignore
        }
//        USER_CACHE.put(user.getCacheKey(), user);
        return SecurityRegisterResponse.newBuilder()
                .setUserId(userId)
                .setToken(getToken(header, userId))
                .build();
    }

    public SecurityLoginResponse login(Header header, Long userId, String password, boolean isQuickLogin) {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (user == null) {
            return SecurityLoginResponse.newBuilder().setRet(BrokerErrorCode.LOGIN_INPUTS_ERROR.code()).build();
        }
        if (!isQuickLogin && !user.getPassword().equals(CryptoUtil.encryptPassword(password, user.getSnow()))) {
            return SecurityLoginResponse.newBuilder().setRet(BrokerErrorCode.LOGIN_INPUTS_ERROR.code()).build();
        }
        if (user.getUserStatus() != USER_ENABLE_STATUS) {
            log.info("user:{} status is disable. return user status forbidden", userId);
            return SecurityLoginResponse.newBuilder().setRet(BrokerErrorCode.USER_STATUS_FORBIDDEN.code()).build();
        }
        if (Strings.nullToEmpty(user.getGaKey()).length() == 16
                && Strings.nullToEmpty(redisTemplate.opsForValue().get("forceUpdateKeys")).equals("1")) {
            refreshUserGaKey(header.getOrgId(), userId);
            userApiKeyService.refreshUserApiKey(header.getOrgId(), userId);
        }
        try {
            redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(user), USER_CACHE_SECOND, TimeUnit.SECONDS);
        } catch (Exception e) {
            // ignore
        }
//        USER_CACHE.put(user.getCacheKey(), user);
        return SecurityLoginResponse.newBuilder()
                .setToken(getToken(header, user.getUserId()))
                .build();
    }

    public SecurityUpdateUserStatusResponse updateUserStatus(Header header, Long userId, Integer status) {
        if (status == SecurityUser.UserStatus.UNKNOWN_VALUE) {
            return SecurityUpdateUserStatusResponse.newBuilder().setRet(BrokerErrorCode.PARAM_ERROR.code()).build();
        }
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (user.getUserStatus().intValue() != status) {
            User updateObj = User.builder()
                    .id(user.getId())
                    .userStatus(status)
                    .updated(System.currentTimeMillis()).build();
            userMapper.update(updateObj);
        }
        redisTemplate.delete(user.getCacheKey());
//        USER_CACHE.put(user.getCacheKey(), userMapper.getByUserId(header.getOrgId(), userId));
        return SecurityUpdateUserStatusResponse.getDefaultInstance();
    }

    public User refreshUserCache(Long orgId, Long userId) {
        User user = userMapper.getByUserId(orgId, userId);
        if (user != null) {
            redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(user), USER_CACHE_SECOND, TimeUnit.SECONDS);
//            USER_CACHE.put(user.getCacheKey(), userMapper.getByUserId(orgId, userId));
        }
        return user;
    }

    public String getUserCache(Long orgId, Long userId) {
        User user = User.builder().orgId(orgId).userId(userId).build();
        return redisTemplate.opsForValue().get(user.getCacheKey());
    }

    /**
     * generate loginToken
     * put orgId, platform, userAgent in claims, use sha-512 for sign
     *
     * @param header {@link Header}
     * @param userId userId
     * @return token
     */
    public String getToken(Header header, Long userId) {
        if (header.getPlatform() == Platform.MOBILE && Strings.isNullOrEmpty(header.getAppBaseHeader().getImei())) {
            log.warn("MOBILE-LOGIN-NO-IMEI-WARNING: orgId:{} userId:{} login by mobile with header:{}, no imei.",
                    header.getOrgId(), userId, JsonUtil.defaultGson().toJson(header));
        }
        String randomKey = CryptoUtil.getRandomCode(12);
        if ((header.getPlatform() == Platform.MOBILE && header.getRequestUri().startsWith("/mapi"))
                || (header.getPlatform() == Platform.MOBILE && header.getRequestUri().startsWith("/openapi"))
                || (header.getPlatform() == Platform.MOBILE && header.getRequestUri().startsWith("/api") && !Strings.isNullOrEmpty(header.getAppBaseHeader().getImei()))) {
            randomKey = header.getAppBaseHeader().getImei();
            return Jwts.builder()
                    .setSubject(userId.toString())
                    .claim(SecurityConstants.VERSION_KEY, APP_SECURITY_TOKEN_VERSION)
                    .claim(SecurityConstants.REQUEST_TIME, System.currentTimeMillis())
                    .claim(SecurityConstants.RANDOM_KEY, randomKey)
                    .claim(SecurityConstants.PLATFORM_KEY, Hashing.md5().hashString(
                            randomKey + header.getPlatform().name(), Charsets.UTF_8).toString())
                    .signWith(SignatureAlgorithm.HS256, getTokenEncryptPassword())
                    .compact();
        }
        return Jwts.builder()
                .setSubject(userId.toString())
                .claim(SecurityConstants.REQUEST_TIME, System.currentTimeMillis())
                .claim(SecurityConstants.RANDOM_KEY, randomKey)
                .claim(SecurityConstants.PLATFORM_KEY, Hashing.md5().hashString(
                        randomKey + header.getPlatform().name(), Charsets.UTF_8).toString())
                .signWith(SignatureAlgorithm.HS256, getTokenEncryptPassword())
                .compact();
    }

    public SecurityVerifyLoginResponse verifyLogin(Header header, String token, boolean isSocketConnect) {
        try {
            Claims claims = Jwts.parser().setSigningKey(getTokenEncryptPassword()).parseClaimsJws(token).getBody();
            String randomKey = claims.get(SecurityConstants.RANDOM_KEY).toString();
            String hashPlatform = claims.get(SecurityConstants.PLATFORM_KEY).toString();
            String hashValue = Hashing.md5().hashString(randomKey + header.getPlatform().name(), Charsets.UTF_8).toString();
            if (!hashValue.equals(hashPlatform)) {
                log.warn("{}-{} verify Login status error, check claims randomHash: md5({} + {}) is wrong", header.getOrgId(), header.getUserId(), randomKey, header.getPlatform());
                return SecurityVerifyLoginResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            // 校验手机端的设备信息
            if (((header.getPlatform() == Platform.MOBILE && header.getRequestUri().startsWith("/mapi"))
                    || (header.getPlatform() == Platform.MOBILE && header.getRequestUri().startsWith("/api") && !Strings.isNullOrEmpty(header.getAppBaseHeader().getImei())))
                    && claims.containsKey(SecurityConstants.VERSION_KEY) && !isSocketConnect) {
                if (!header.getAppBaseHeader().getImei().equals(randomKey)) {
                    log.warn("{}-{} verify Login status error, check app header(imei:{}) is wrong, randomKey:{}",
                            header.getOrgId(), claims.getSubject(), header.getAppBaseHeader().getImei(), randomKey);
                    if (header.getOrgId() != 7138 && header.getOrgId() != 7137) {
                        return SecurityVerifyLoginResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
                    }
                }
            }
            Long userId = Long.valueOf(claims.getSubject());
            User user = getCacheUser(header.getOrgId(), userId);
            if (user == null) {
                return SecurityVerifyLoginResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            if (user.getUserStatus() != USER_ENABLE_STATUS) {
                log.info("user:{} status is disable. return authorize error", userId);
                return SecurityVerifyLoginResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            return SecurityVerifyLoginResponse.newBuilder()
                    .setUserId(userId)
                    .build();
        } catch (Exception e) {
            log.warn("verify Login status error: {}", Throwables.getStackTraceAsString(e));
            return SecurityVerifyLoginResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
        }
    }

    public SecurityRefreshTokenResponse refreshToken(Header header, String token, Boolean generateNewToken) {
//        Claims claims = Jwts.parser().setSigningKey(getTokenEncryptPassword()).parseClaimsJws(token).getBody();
//        String randomKey = claims.get(SecurityConstants.RANDOM_KEY).toString();
//        String hashPlatform = claims.get(SecurityConstants.PLATFORM_KEY).toString();
//        String hashValue = Hashing.md5().hashString(randomKey + header.getPlatform().name(), Charsets.UTF_8).toString();
//        if (!hashValue.equals(hashPlatform)) {
//            log.warn("verify Login status error, claims is wrong");
//            return SecurityRefreshTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
//        }
//        Long userId = Long.valueOf(claims.getSubject());
//        User user = userMapper.getByUserId(header.getOrgId(), userId);
//        if (user == null) {
//            return SecurityRefreshTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
//        }
//        if (user.getUserStatus() != USER_ENABLE_STATUS) {
//            log.info("user:{} status is disable. return authorize error", userId);
//            return SecurityRefreshTokenResponse.newBuilder().setRet(BrokerErrorCode.USER_STATUS_FORBIDDEN.code()).build();
//        }
        SecurityVerifyLoginResponse response = verifyLogin(header, token, false);
        if (response.getRet() != 0) {
            log.warn("refresh token error, oldToken check failed");
            return SecurityRefreshTokenResponse.newBuilder().setRet(response.getRet()).build();
        }
        return SecurityRefreshTokenResponse.newBuilder()
                .setToken(generateNewToken ? getToken(header, response.getUserId()) : token)
                .setUserId(response.getUserId())
                .build();
    }

    public SecurityParseTokenResponse parseToken(Header header, String token, String tokenFrom) {
        try {
            if (Strings.isNullOrEmpty(token)) {
                return SecurityParseTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            Claims claims = Jwts.parser().setSigningKey(getTokenEncryptPassword()).parseClaimsJws(token).getBody();
            String randomKey = claims.get(SecurityConstants.RANDOM_KEY).toString();
            String hashPlatform = claims.get(SecurityConstants.PLATFORM_KEY).toString();
            String hashValue = Hashing.md5().hashString(randomKey + tokenFrom, Charsets.UTF_8).toString();
            if (!hashValue.equals(hashPlatform)) {
                return SecurityParseTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            Long userId = Long.valueOf(claims.getSubject());
            User user = userMapper.getByUserId(header.getOrgId(), userId);
            if (user == null) {
                return SecurityParseTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
            }
            return SecurityParseTokenResponse.newBuilder()
                    .setUserId(userId)
                    .setStatus(user.getUserStatus())
                    .build();
        } catch (Exception e) {
            log.warn(" parseToken token:{} error", token, e);
            return SecurityParseTokenResponse.newBuilder().setRet(BrokerErrorCode.AUTHORIZE_ERROR.code()).build();
        }
    }

    public SecurityBeforeBindGAResponse beforeBindGa(Header header, Long userId, String gaIssuer, String accountName) throws Exception {
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        User user = userMapper.getByUserId(header.getOrgId(), header.getUserId());
        String gaKey = key.getKey(), encryptGaKey = SignUtil.encryptData(getKey(user), key.getKey());
        UserBindGACheck bindGACheck = UserBindGACheck.builder()
                .orgId(header.getOrgId())
                .userId(userId)
                .gaKey(encryptGaKey)
                .expired(System.currentTimeMillis() + 2 * 3600 * 1000)
                .created(System.currentTimeMillis())
                .build();
        userMapper.insertUserBindGACheck(bindGACheck);
        if (Strings.isNullOrEmpty(accountName)) {
            accountName = "******" + userId.toString().substring(userId.toString().length() - 6);
        }
        String otpAuthTotpURL = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(gaIssuer, accountName, key);
        return SecurityBeforeBindGAResponse.newBuilder()
                .setOtpAuthTotpUrl(otpAuthTotpURL)
                .setKey(gaKey)
                .build();
    }

    public SecurityBindGAResponse bindGA(Header header, Long userId, Integer gaCode) throws Exception {
        UserBindGACheck bindGACheck = userMapper.getLastBindGaCheck(header.getOrgId(), userId);
        if (bindGACheck == null) {
            log.warn("cannot find user bind_ga check record, maybe this request is invalid, userId:{}", userId);
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (bindGACheck.getExpired() < System.currentTimeMillis()) {
            log.error("user bind_ga check record is expired, userId:{}", userId);
        }
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        String gaKey = bindGACheck.getGaKey(), encryptGaKey = bindGACheck.getGaKey();
        if (gaKey.length() > 16) {
            gaKey = SignUtil.decryptData(getKey(user), bindGACheck.getGaKey());
        } else {
            encryptGaKey = SignUtil.encryptData(getKey(user), encryptGaKey);
        }
        if (!googleAuthenticator.authorize(gaKey, gaCode, System.currentTimeMillis())) {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.GA_VALID_ERROR.code()).build();
        }
        if (Strings.isNullOrEmpty(user.getGaKey())) {
            User updateObj = User.builder()
                    .id(user.getId())
                    .gaKey(encryptGaKey)
                    .updated(System.currentTimeMillis())
                    .build();
            userMapper.update(updateObj);
            return SecurityBindGAResponse.newBuilder().build();
        } else {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.GA_UNBIND_FIRST.code()).build();
        }
    }

    public SecurityBindGAResponse bindGADirect(Header header, Long userId, String gaKey, Integer gaCode) throws Exception {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        String encryptGaKey = SignUtil.encryptData(getKey(user), gaKey);
        if (!googleAuthenticator.authorize(gaKey, gaCode, System.currentTimeMillis())) {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.GA_VALID_ERROR.code()).build();
        }
        if (Strings.isNullOrEmpty(user.getGaKey())) {
            User updateObj = User.builder()
                    .id(user.getId())
                    .gaKey(encryptGaKey)
                    .updated(System.currentTimeMillis())
                    .build();
            userMapper.update(updateObj);
            return SecurityBindGAResponse.newBuilder().build();
        } else {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.GA_UNBIND_FIRST.code()).build();
        }
    }

    public SecurityVerifyGAResponse verifyGA(Header header, Long userId, Integer gaCode) throws Exception {
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        String gaKey = user.getGaKey();
        if (gaKey.length() > 16) {
            gaKey = SignUtil.decryptData(getKey(user), gaKey);
        }
        if (!googleAuthenticator.authorize(gaKey, gaCode, System.currentTimeMillis())) {
            return SecurityVerifyGAResponse.newBuilder().setRet(BrokerErrorCode.GA_VALID_ERROR.code()).build();
        }
        return SecurityVerifyGAResponse.newBuilder().build();
    }

    public SecurityUnBindGAResponse unBindGA(Header header, Long userId) {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        User updateObj = User.builder()
                .id(user.getId())
                .gaKey("")
                .updated(System.currentTimeMillis())
                .build();
        userMapper.update(updateObj);
        return SecurityUnBindGAResponse.newBuilder().build();
    }

    public SecurityResetPasswordResponse resetPassword(Header header, Long userId, String password) {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (Strings.isNullOrEmpty(password)) {
            return SecurityResetPasswordResponse.newBuilder().setRet(BrokerErrorCode.PASSWORD_CANNOT_BE_NULL.code()).build();
        }
        updateUserPassword(user, password, PasswordChangeType.FORGET_PASSWORD);
        return SecurityResetPasswordResponse.newBuilder().build();
    }

    public SecurityUpdatePasswordResponse updatePassword(Header header, Long userId, String oldPassword, String newPassword, boolean firstSetPassword) {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (Strings.isNullOrEmpty(newPassword)) {
            return SecurityUpdatePasswordResponse.newBuilder().setRet(BrokerErrorCode.NEW_PASSWORD_CANNOT_BE_NULL.code()).build();
        }
        if (!firstSetPassword && header.getPlatform() != Platform.ORG_API) {
            if (!user.getPassword().equals(CryptoUtil.encryptPassword(oldPassword, user.getSnow()))) {
                return SecurityUpdatePasswordResponse.newBuilder().setRet(BrokerErrorCode.OLD_PASSWORD_ERROR.code()).build();
            }
        }
        updateUserPassword(user, newPassword, PasswordChangeType.UPDATE_PASSWORD);
        return SecurityUpdatePasswordResponse.newBuilder().build();
    }

    private void updateUserPassword(User user, String newPassword, PasswordChangeType changeType) {
        String snow = CryptoUtil.getRandomCode(8);
        Long timestamp = System.currentTimeMillis();
        User updateObj = User.builder()
                .id(user.getId())
                .userId(user.getUserId())
                .password(CryptoUtil.encryptPassword(newPassword, snow))
                .snow(snow)
                .updated(timestamp)
                .build();
        try {
            if (!Strings.isNullOrEmpty(user.getGaKey()) && user.getGaKey().length() > 16) {
                String gaKey = SignUtil.decryptData(getKey(user), user.getGaKey());
                updateObj.setGaKey(SignUtil.encryptData(getKey(updateObj), gaKey));
            }
        } catch (Exception e) {
            log.error("reset gaKey after updatePassword error, please handle. orgId:{}, userId:{}", user.getOrgId(), user.getUserId(), e);
        }
        userMapper.update(updateObj);
        UserPwdChangeLog changeLog = UserPwdChangeLog.builder()
                .userId(user.getUserId())
                .changeType(changeType.getNumber())
                .oldPassword(user.getPassword())
                .oldSnow(user.getSnow())
                .newPassword(updateObj.getPassword())
                .newSnow(updateObj.getSnow())
                .created(timestamp)
                .build();
        userPwdChangeLogMapper.insert(changeLog);
    }

    public SecuritySendVerifyCodeResponse sendEmailVerifyCode(Header header, Long userId, String email,
                                                              SecurityVerifyCodeType verifyCodeType, String language) {
        if (verifyCaptcha && globalNotifyType == 2) {
            //仅支持手机发送，告警
            log.warn("not allow sendEmailVerifyCode!{},{}", header.getOrgId(), userId);
        }

        String code = RandomStringUtils.random(6, false, true);
        String index = RandomStringUtils.random(3, false, true);
        Long orderId = sequenceGenerator.getLong();

        List<String> params = Collections.singletonList(code);
        SimpleMailRequest request = SimpleMailRequest.newBuilder()
                .setOrgId(header.getOrgId())
                .setMail(email)
                .setBusinessType(verifyCodeType.name())
                .setLanguage(header.getLanguage())
                .addAllParams(params)
                .setUserId(userId != null ? userId : 0L)
                .setReqOrderId(orderId.toString())
                .setIp(header.getRemoteIp())
                .build();
        boolean result = grpcEmailService.sendEmailVerifyCode(request);
        log.info("orgId:{} userId:{} verifyCodeType:{} mail:{} sendEmailVerifyCode {}",
                header.getOrgId(), userId, verifyCodeType, email, result);
        if (!result) {
            return SecuritySendVerifyCodeResponse.newBuilder().setRet(BrokerErrorCode.VERIFY_CODE_SEND_FAILED.code()).build();
        }
        cacheVerifyCodeOrderId(header, userId, email, orderId, code, verifyCodeType.getNumber());
        return SecuritySendVerifyCodeResponse.newBuilder().setOrderId(orderId).setIndex(index).build();
    }

    public SecuritySendVerifyCodeResponse sendMobileVerifyCode(Header header, Long userId, String nationalCode, String mobile,
                                                               SecurityVerifyCodeType verifyCodeType, String language) {
        if (verifyCaptcha && globalNotifyType == 3) {
            //仅支持邮箱发送，告警
            log.warn("not allow sendMobileVerifyCode!{},{}", header.getOrgId(), userId);
        }

        String code = RandomStringUtils.random(6, false, true);
        String index = RandomStringUtils.random(3, false, true);
        Long orderId = sequenceGenerator.getLong();

        List<String> params = Collections.singletonList(code);
        SimpleSMSRequest request = SimpleSMSRequest.newBuilder()
                .setOrgId(header.getOrgId())
                .setTelephone(Telephone.newBuilder().setNationCode(nationalCode).setMobile(mobile).build())
                .setBusinessType(verifyCodeType.name())
                .setLanguage(header.getLanguage())
                .addAllParams(params)
                .setUserId(userId != null ? userId : 0L)
                .setReqOrderId(orderId.toString())
                .setIp(header.getRemoteIp())
                .build();
        boolean result = grpcSmsService.sendSmsVerifyCode(request);
        log.info("orgId:{} userId:{} verifyCodeType:{} mobile:{} sendMobileVerifyCode {}",
                header.getOrgId(), userId, verifyCodeType, mobile, result);
        if (!result) {
            return SecuritySendVerifyCodeResponse.newBuilder().setRet(BrokerErrorCode.VERIFY_CODE_SEND_FAILED.code())
                    .build();
        }
        cacheVerifyCodeOrderId(header, userId, nationalCode + mobile, orderId, code, verifyCodeType.getNumber());
        return SecuritySendVerifyCodeResponse.newBuilder().setOrderId(orderId).setIndex(index).build();
    }

    public SecurityValidVerifyCodeResponse validVerifyCode(Header header, Long userId, String receiver,
                                                           Long verifyCodeOrderId, String verifyCode, Integer verifyCodeType) {
        if (!checkVerifyCode(header, userId, receiver, verifyCodeOrderId, verifyCode, verifyCodeType)) {
            return SecurityValidVerifyCodeResponse.newBuilder().setRet(BrokerErrorCode.VERIFY_CODE_ERROR.code()).build();
        }
        return SecurityValidVerifyCodeResponse.newBuilder().build();
    }

    public SecurityInvalidVerifyCodeResponse invalidVerifyCode(Header header, Long userId, String receiver,
                                                               Long verifyCodeOrderId, Integer verifyCodeType) {
        String receiverKey = receiver;
        if (skipReceiver(userId, verifyCodeType)) {
            receiverKey = "";
        }
        String verifyCodeKey = String.format(VERIFY_CODE_KEY, header.getOrgId(), userId, receiverKey, verifyCodeOrderId, verifyCodeType);
        log.debug("invalid verification key: {}", verifyCodeKey);
        redisTemplate.delete(verifyCodeKey);
        return SecurityInvalidVerifyCodeResponse.newBuilder().build();
    }

    public SecuritySetTradePasswordResponse setTradePassword(Header header, Long userId, String tradePassword) {
        if (Strings.isNullOrEmpty(tradePassword)) {
            return SecuritySetTradePasswordResponse.newBuilder()
                    .setRet(BrokerErrorCode.TRADE_PWD_CANNOT_BE_NULL.code())
                    .build();
        }
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (user.getPassword().equals(CryptoUtil.encryptPassword(tradePassword, user.getSnow()))) {
            return SecuritySetTradePasswordResponse.newBuilder()
                    .setRet(BrokerErrorCode.PWD_CANNOT_EQ_TRADE_PWD.code())
                    .build();
        }

        String snow = CryptoUtil.getRandomCode(8);
        Long timestamp = System.currentTimeMillis();
        User updateObj = User.builder()
                .id(user.getId())
                .tradePassword(CryptoUtil.encryptPassword(tradePassword, snow))
                .tradeSnow(snow)
                .updated(timestamp)
                .build();
        userMapper.update(updateObj);
        return SecuritySetTradePasswordResponse.newBuilder().build();
    }

    public SecurityVerifyTradePasswordResponse verifyTradePassword(Header header, Long userId, String tradePassword) {
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        if (user == null
                || !user.getTradePassword().equals(CryptoUtil.encryptPassword(tradePassword, user.getTradeSnow()))) {
            return SecurityVerifyTradePasswordResponse.newBuilder()
                    .setRet(BrokerErrorCode.TRADE_PASSWORD_VERIFY_FAILED.code())
                    .build();
        }
        return SecurityVerifyTradePasswordResponse.newBuilder().build();
    }

    /**
     * redis.getString(orderId).equals(sha512(orgId + userId + orderId + verifyCodeType))
     *
     * @param header         {@link Header}
     * @param userId         userId, in the non-login state is 0.
     * @param receiver       who receive verifyCode?email or (nationalCode + mobile)
     * @param orderId        orderId for send verify code
     * @param verifyCode     random verifyCode
     * @param verifyCodeType {@link SecurityVerifyCodeType}
     * @return true or false
     */
    private Boolean checkVerifyCode(Header header, Long userId, String receiver, Long orderId,
                                    String verifyCode, Integer verifyCodeType) {
        if (!verifyCaptcha) {
            return "123456".equals(verifyCode);
        }
        String receiverKey = receiver;
        if (skipReceiver(userId, verifyCodeType)) {
            receiverKey = "";
        }
        verifyCode = Hashing.md5().hashString(verifyCode, Charsets.UTF_8).toString();
        String verifyCodeKey = String.format(VERIFY_CODE_KEY, header.getOrgId(), userId, receiverKey, orderId, verifyCodeType);
        try {
            String invokeTimesKey = String.format("CODE_ID:%s_%s", header.getOrgId(), orderId);
            long invokeTimes = 0;
            if ((invokeTimes = redisTemplate.opsForValue().increment(invokeTimesKey)) > 5) {
                log.error("orgId:{} userId:{} requestIp:{} is trying to crack the {} {} verification code with orderId:{} {} times",
                        header.getOrgId(), header.getUserId(), header.getRemoteIp(), receiver, SecurityVerifyCodeType.forNumber(verifyCodeType), orderId, invokeTimes);
                return false;
            }
            if (!redisTemplate.hasKey(verifyCodeKey)) {
                log.warn("verifyCode(key:{}) cache does not exists", verifyCodeKey);
                return false;
            }
            boolean validResult = verifyCode.equals(redisTemplate.opsForValue().get(verifyCodeKey));
            codeFeedback(header.getOrgId(), orderId, validResult, receiver);
            return validResult;
        } catch (Exception e) {
            log.error("check verify code(key:{}) from cache error, check from db", verifyCodeKey, e);
            boolean validResult = checkVerifyCodeFromDB(header, userId, receiver, orderId, verifyCode, verifyCodeType);
            codeFeedback(header.getOrgId(), orderId, validResult, receiver);
            return validResult;
        }
    }

    /**
     * verifyCode is encrypt value
     */
    private Boolean checkVerifyCodeFromDB(Header header, Long userId, String receiver, Long orderId,
                                          String verifyCode, Integer verifyCodeType) {
        VerifyCode record = verifyCodeMapper.get(orderId);
        if (record == null) {
            log.warn("verifyCode record not found, request Param is orgId:{} userId:{} receiver:{}, orderId:{}, type:{}",
                    header.getOrgId(), userId, receiver, orderId, verifyCodeType);
            return false;
        }
        if (record.getUserId() != userId.longValue() || record.getType() != verifyCodeType.intValue()
                || (skipReceiver(userId, verifyCodeType) && !receiver.equals(record.getReceiver()))) {
            log.warn("verifyCode record is :{}, request Param is orgId:{} userId:{} receiver:{}, orderId:{}, type:{}",
                    JsonUtil.defaultGson().toJson(record), header.getOrgId(), userId, receiver, orderId, verifyCodeType);
            return false;
        }
        return verifyCode.equals(record.getCode());
    }

    private boolean skipReceiver(Long userId, Integer verifyCodeType) {
        return userId > 0
                && verifyCodeType != SecurityVerifyCodeType.BIND_MOBILE.getNumber()
                && verifyCodeType != SecurityVerifyCodeType.BIND_EMAIL.getNumber()
                && verifyCodeType != SecurityVerifyCodeType.REBIND_MOBILE.getNumber()
                && verifyCodeType != SecurityVerifyCodeType.REBIND_EMAIL.getNumber();
    }

    /**
     * Cache a key for verifying the verification code
     * Key: orderId
     * Value: sha512(orgId + userId + orderId + verifyCodeType)
     *
     * @param header         {@link Header}
     * @param userId         userId, in the non-login state is 0.
     * @param receiver       who receive verifyCode?email or (nationalCode + mobile)
     * @param orderId        orderId for send verify code
     * @param verifyCode     random verifyCode
     * @param verifyCodeType {@link SecurityVerifyCodeType}
     */
    private void cacheVerifyCodeOrderId(Header header, Long userId, String receiver, Long orderId,
                                        String verifyCode, Integer verifyCodeType) {
        String receiverKey = receiver;
        if (skipReceiver(userId, verifyCodeType)) {
            receiverKey = "";
        }
        verifyCode = Hashing.md5().hashString(verifyCode, Charsets.UTF_8).toString();
        String verifyCodeKey = String.format(VERIFY_CODE_KEY, header.getOrgId(), userId, receiverKey, orderId, verifyCodeType);
        try {
            redisTemplate.opsForValue().set(verifyCodeKey, verifyCode, 10, TimeUnit.MINUTES);
        } catch (Exception e) {
            log.error("cache verify code(key:{}, value:{}) error", verifyCodeKey, e);
        }
        try {
            verifyCodeMapper.insert(
                    VerifyCode.builder().id(orderId)
                            .orgId(header.getOrgId())
                            .userId(header.getUserId())
                            .receiver(receiver)
                            .type(verifyCodeType)
                            .code(verifyCode)
                            .content("ignore")
                            .created(System.currentTimeMillis())
                            .build());
        } catch (Exception e) {
            log.error("save verify code(key:{}) into db error", verifyCodeKey, e);
        }
    }

    public String getTokenEncryptPassword() {
        if (Strings.isNullOrEmpty(TOKEN_ENCRYPT_PASSWORD)) {
            return securityProperties.getSecretKey();
        }
        return TOKEN_ENCRYPT_PASSWORD;
    }

    public String getKey(User user) {
        return user.getUserId() + "*" + user.getSnow();
    }

    public void refreshUserGaKey(Long orgId, Long userId) {
        try {
            User user = userMapper.getByUserId(orgId, userId);
            if (user != null && !Strings.isNullOrEmpty(user.getGaKey()) && user.getGaKey().length() == 16) {
                User updateObj = User.builder()
                        .id(user.getId())
                        .gaKey(SignUtil.encryptData(getKey(user), user.getGaKey()))
                        .updated(System.currentTimeMillis())
                        .build();
                userMapper.update(updateObj);
            }
        } catch (Exception e) {
            log.error("refresh user gaKey error");
        }
    }

    public User getCacheUser(Long orgId, Long userId) {
        if (orgId == null || userId == null) {
            return null;
        }
        try {
            String userCacheKey = User.builder().orgId(orgId).userId(userId).build().getCacheKey();
            if (redisTemplate.hasKey(userCacheKey) && !Strings.isNullOrEmpty(redisTemplate.opsForValue().get(userCacheKey))) {
                return JsonUtil.defaultGson().fromJson(redisTemplate.opsForValue().get(userCacheKey), User.class);
            } else {
                User user = userMapper.getByUserId(orgId, userId);
                redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(user), USER_CACHE_SECOND, TimeUnit.SECONDS);
                return user;
            }
//            return USER_CACHE.get(User.builder().orgId(orgId).userId(userId).build().getCacheKey());
        } catch (Exception e) {
            return userMapper.getByUserId(orgId, userId);
        }
    }

    public void resetUserGaKey(Long orgId, Long userId) throws Exception {
        User user = userMapper.getByUserId(orgId, userId);
        if (user != null && user.getGaKey().length() > 16) {
            try {
                SignUtil.decryptData(getKey(user), user.getGaKey());
            } catch (BadPaddingException e) {
                List<UserPwdChangeLog> changeLogs = userPwdChangeLogMapper.queryChangePwdLogs(userId);
                if (!CollectionUtils.isEmpty(changeLogs)) {
                    for (UserPwdChangeLog changeLog : changeLogs) {
                        User gaKeyUser = User.builder().userId(userId).snow(changeLog.getOldSnow()).build();
                        try {
                            String gaKey = SignUtil.decryptData(getKey(gaKeyUser), user.getGaKey());
                            User updateObj = User.builder()
                                    .id(user.getId())
                                    .gaKey(SignUtil.encryptData(getKey(user), gaKey))
                                    .updated(System.currentTimeMillis())
                                    .build();
                            userMapper.update(updateObj);
                            log.info("reset success.errorGAKey:{}, rightGAKey:{}", user.getGaKey(), updateObj.getGaKey());
                            break;
                        } catch (Exception ignoreE) {
                            log.warn("reset gaKey error", ignoreE);
                        }
                    }
                }
            }
        }
    }

    public Boolean updateApiLevel(Long orgId, Long userId, Integer apiLevel) {
        User user = userMapper.getByUserId(orgId, userId);
        User updateObj = User.builder()
                .id(user.getId())
                .apiLevel(apiLevel)
                .updated(System.currentTimeMillis())
                .build();
        userMapper.update(updateObj);
        try {
            redisTemplate.opsForValue().set(user.getCacheKey(), JsonUtil.defaultGson().toJson(userMapper.getByUserId(orgId, userId)), USER_CACHE_SECOND, TimeUnit.SECONDS);
        } catch (Exception e) {
            // ignore
        }
        return JsonUtil.defaultGson().fromJson(redisTemplate.opsForValue().get(user.getCacheKey()), User.class).getApiLevel() == apiLevel;
//        USER_CACHE.put(user.getCacheKey(), userMapper.getByUserId(orgId, userId));
    }

    public void codeFeedback(long orgId, long orderId, boolean validResult, String receiver) {
        try {
            CodeFeedbackRequest codeFeedbackRequest = CodeFeedbackRequest.newBuilder()
                    .setOrgId(orgId)
                    .setReqOrderId(orderId + "")
                    .setValidResult(validResult)
                    .setValidTime(System.currentTimeMillis())
                    .setType(receiver.contains("@") ? CodeFeedbackRequest.MessageType.EMAIL : CodeFeedbackRequest.MessageType.SMS)
                    .build();
            grpcCodeFeedbackService.codeFeedback(codeFeedbackRequest);
        } catch (Exception ignoreE) {
            log.warn("codeFeedback error", ignoreE);
        }
    }

    public SecurityBindGAResponse alterBindGA(Header header, Long userId, Integer gaCode) throws Exception {
        UserBindGACheck bindGACheck = userMapper.getLastBindGaCheck(header.getOrgId(), userId);
        if (bindGACheck == null) {
            log.warn("alterBindGA error with cannot find user bind_ga check record, maybe this request is invalid, userId:{}", userId);
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.REQUEST_INVALID.code()).build();
        }
        if (bindGACheck.getExpired() < System.currentTimeMillis()) {
            log.error("alterBindGA error with user bind_ga check record is expired, userId:{}", userId);
        }
        User user = userMapper.getByUserId(header.getOrgId(), userId);
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
        String gaKey = bindGACheck.getGaKey(), encryptGaKey = bindGACheck.getGaKey();
        if (gaKey.length() > 16) {
            gaKey = SignUtil.decryptData(getKey(user), bindGACheck.getGaKey());
        } else {
            encryptGaKey = SignUtil.encryptData(getKey(user), encryptGaKey);
        }
        if (!googleAuthenticator.authorize(gaKey, gaCode, System.currentTimeMillis())) {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.REBIND_GA_VALID_ERROR.code()).build();
        }
        if (!Strings.isNullOrEmpty(user.getGaKey())) {
            User updateObj = User.builder()
                    .id(user.getId())
                    .gaKey(encryptGaKey)
                    .updated(System.currentTimeMillis())
                    .build();
            userMapper.update(updateObj);
            return SecurityBindGAResponse.newBuilder().build();
        } else {
            return SecurityBindGAResponse.newBuilder().setRet(BrokerErrorCode.NEED_BIND_GA.code()).build();
        }
    }

}
