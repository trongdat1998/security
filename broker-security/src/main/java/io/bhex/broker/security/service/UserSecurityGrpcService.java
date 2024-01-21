/**********************************
 *@项目名称: broker-proto
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/7/26
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import javax.annotation.Resource;

import io.bhex.base.grpc.annotation.GrpcService;
import io.bhex.base.grpc.server.interceptor.GrpcServerLogInterceptor;
import io.bhex.broker.common.exception.BrokerException;
import io.bhex.broker.grpc.security.ChangeUserApiLevelRequest;
import io.bhex.broker.grpc.security.ChangeUserApiLevelResponse;
import io.bhex.broker.grpc.security.QueryUserTokenRequest;
import io.bhex.broker.grpc.security.QueryUserTokenResponse;
import io.bhex.broker.grpc.security.SecurityBeforeBindGARequest;
import io.bhex.broker.grpc.security.SecurityBeforeBindGAResponse;
import io.bhex.broker.grpc.security.SecurityBindGADirectRequest;
import io.bhex.broker.grpc.security.SecurityBindGARequest;
import io.bhex.broker.grpc.security.SecurityBindGAResponse;
import io.bhex.broker.grpc.security.SecurityCreateApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityCreateApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityDeleteApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityDeleteApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityGetApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityGetApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityInvalidVerifyCodeRequest;
import io.bhex.broker.grpc.security.SecurityInvalidVerifyCodeResponse;
import io.bhex.broker.grpc.security.SecurityLoginRequest;
import io.bhex.broker.grpc.security.SecurityLoginResponse;
import io.bhex.broker.grpc.security.SecurityParseTokenRequest;
import io.bhex.broker.grpc.security.SecurityParseTokenResponse;
import io.bhex.broker.grpc.security.SecurityQueryOrgAuthorizedAccountApiKeysRequest;
import io.bhex.broker.grpc.security.SecurityQueryUserApiKeysRequest;
import io.bhex.broker.grpc.security.SecurityQueryUserApiKeysResponse;
import io.bhex.broker.grpc.security.SecurityRefreshTokenRequest;
import io.bhex.broker.grpc.security.SecurityRefreshTokenResponse;
import io.bhex.broker.grpc.security.SecurityRegisterRequest;
import io.bhex.broker.grpc.security.SecurityRegisterResponse;
import io.bhex.broker.grpc.security.SecurityResetPasswordRequest;
import io.bhex.broker.grpc.security.SecurityResetPasswordResponse;
import io.bhex.broker.grpc.security.SecuritySendEmailVerifyCodeRequest;
import io.bhex.broker.grpc.security.SecuritySendMobileVerifyCodeRequest;
import io.bhex.broker.grpc.security.SecuritySendVerifyCodeResponse;
import io.bhex.broker.grpc.security.SecurityServiceGrpc;
import io.bhex.broker.grpc.security.SecuritySetTradePasswordRequest;
import io.bhex.broker.grpc.security.SecuritySetTradePasswordResponse;
import io.bhex.broker.grpc.security.SecurityUnBindGARequest;
import io.bhex.broker.grpc.security.SecurityUnBindGAResponse;
import io.bhex.broker.grpc.security.SecurityUpdateApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityUpdateApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityUpdatePasswordRequest;
import io.bhex.broker.grpc.security.SecurityUpdatePasswordResponse;
import io.bhex.broker.grpc.security.SecurityUpdateUserStatusRequest;
import io.bhex.broker.grpc.security.SecurityUpdateUserStatusResponse;
import io.bhex.broker.grpc.security.SecurityValidApiAccessRequest;
import io.bhex.broker.grpc.security.SecurityValidApiAccessResponse;
import io.bhex.broker.grpc.security.SecurityValidApiKeyRequest;
import io.bhex.broker.grpc.security.SecurityValidApiKeyResponse;
import io.bhex.broker.grpc.security.SecurityValidVerifyCodeRequest;
import io.bhex.broker.grpc.security.SecurityValidVerifyCodeResponse;
import io.bhex.broker.grpc.security.SecurityVerifyGARequest;
import io.bhex.broker.grpc.security.SecurityVerifyGAResponse;
import io.bhex.broker.grpc.security.SecurityVerifyLoginRequest;
import io.bhex.broker.grpc.security.SecurityVerifyLoginResponse;
import io.bhex.broker.grpc.security.SecurityVerifyTradePasswordRequest;
import io.bhex.broker.grpc.security.SecurityVerifyTradePasswordResponse;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@GrpcService(interceptors = {GrpcServerLogInterceptor.class})
public class UserSecurityGrpcService extends SecurityServiceGrpc.SecurityServiceImplBase {

    @Resource
    private UserSecurityService userSecurityService;

    @Resource
    private UserApiKeyService userApiKeyService;

    @Override
    public void register(SecurityRegisterRequest request, StreamObserver<SecurityRegisterResponse> observer) {
        try {
            SecurityRegisterResponse response =
                    userSecurityService.register(request.getHeader(), request.getUserId(), request.getPassword());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security register error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void login(SecurityLoginRequest request, StreamObserver<SecurityLoginResponse> observer) {
        try {
            SecurityLoginResponse response =
                    userSecurityService.login(request.getHeader(), request.getUserId(), request.getPassword(), request.getIsQuickLogin());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security login error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void verifyLogin(SecurityVerifyLoginRequest request, StreamObserver<SecurityVerifyLoginResponse> observer) {
        try {
            SecurityVerifyLoginResponse response =
                    userSecurityService.verifyLogin(request.getHeader(), request.getToken(), request.getSocketConnect());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security verifyLogin error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void refreshToken(SecurityRefreshTokenRequest request, StreamObserver<SecurityRefreshTokenResponse> observer) {
        try {
            SecurityRefreshTokenResponse response =
                    userSecurityService.refreshToken(request.getHeader(), request.getToken(), request.getGenerateNewToken());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security refreshToken error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void parseToken(SecurityParseTokenRequest request, StreamObserver<SecurityParseTokenResponse> observer) {
        try {
            SecurityParseTokenResponse response =
                    userSecurityService.parseToken(request.getHeader(), request.getToken(), request.getTokenFrom().name());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security parseToken error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void beforeBindGA(SecurityBeforeBindGARequest request, StreamObserver<SecurityBeforeBindGAResponse> observer) {
        try {
            SecurityBeforeBindGAResponse response =
                    userSecurityService.beforeBindGa(request.getHeader(), request.getUserId(),
                            request.getGaIssuer(), request.getAccountName());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security getGAKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void bindGA(SecurityBindGARequest request, StreamObserver<SecurityBindGAResponse> observer) {
        try {
            SecurityBindGAResponse response =
                    userSecurityService.bindGA(request.getHeader(), request.getUserId(), request.getGaCode());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security bindGA error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void bindGADirect(SecurityBindGADirectRequest request, StreamObserver<SecurityBindGAResponse> observer) {
        try {
            SecurityBindGAResponse response =
                    userSecurityService.bindGADirect(request.getHeader(), request.getUserId(), request.getGaKey(), request.getGaCode());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security bindGA error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void verifyGA(SecurityVerifyGARequest request, StreamObserver<SecurityVerifyGAResponse> observer) {
        try {
            SecurityVerifyGAResponse response =
                    userSecurityService.verifyGA(request.getHeader(), request.getUserId(), request.getGaCode());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security verifyGA error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void unBindGA(SecurityUnBindGARequest request, StreamObserver<SecurityUnBindGAResponse> observer) {
        try {
            SecurityUnBindGAResponse response =
                    userSecurityService.unBindGA(request.getHeader(), request.getUserId());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security verifyGA error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void resetPassword(SecurityResetPasswordRequest request, StreamObserver<SecurityResetPasswordResponse> observer) {
        try {
            SecurityResetPasswordResponse response =
                    userSecurityService.resetPassword(request.getHeader(), request.getUserId(), request.getPassword());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security resetPassword error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void updatePassword(SecurityUpdatePasswordRequest request, StreamObserver<SecurityUpdatePasswordResponse> observer) {
        try {
            SecurityUpdatePasswordResponse response =
                    userSecurityService.updatePassword(request.getHeader(), request.getUserId(), request.getOldPassword(),
                            request.getNewPassword(), request.getFirstSetPassword());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security updatePassword error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void updateUserStatus(SecurityUpdateUserStatusRequest request, StreamObserver<SecurityUpdateUserStatusResponse> observer) {
        try {
            SecurityUpdateUserStatusResponse response =
                    userSecurityService.updateUserStatus(request.getHeader(), request.getUserId(), request.getUserStatus().getNumber());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security updatePassword error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void sendEmailVerifyCode(SecuritySendEmailVerifyCodeRequest request, StreamObserver<SecuritySendVerifyCodeResponse> observer) {
        try {
            SecuritySendVerifyCodeResponse response =
                    userSecurityService.sendEmailVerifyCode(request.getHeader(), request.getUserId(), request.getEmail(),
                            request.getType(), request.getLanguage());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security sendEmailVerifyCode error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void sendMobileVerifyCode(SecuritySendMobileVerifyCodeRequest request, StreamObserver<SecuritySendVerifyCodeResponse> observer) {
        try {
            SecuritySendVerifyCodeResponse response =
                    userSecurityService.sendMobileVerifyCode(request.getHeader(), request.getUserId(),
                            request.getNationalCode(), request.getMobile(), request.getType(), request.getLanguage());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security sendMobileVerifyCode error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void validVerifyCode(SecurityValidVerifyCodeRequest request, StreamObserver<SecurityValidVerifyCodeResponse> observer) {
        try {
            SecurityValidVerifyCodeResponse response =
                    userSecurityService.validVerifyCode(request.getHeader(), request.getUserId(), request.getReceiver(),
                            request.getOrderId(), request.getVerifyCode(), request.getTypeValue());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security validVerifyCode error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void invalidVerifyCode(SecurityInvalidVerifyCodeRequest request, StreamObserver<SecurityInvalidVerifyCodeResponse> observer) {
        try {
            SecurityInvalidVerifyCodeResponse response =
                    userSecurityService.invalidVerifyCode(request.getHeader(), request.getUserId(),
                            request.getReceiver(), request.getOrderId(), request.getTypeValue());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security invalidVerifyCode error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void createApiKey(SecurityCreateApiKeyRequest request, StreamObserver<SecurityCreateApiKeyResponse> observer) {
        try {
            SecurityCreateApiKeyResponse response = userApiKeyService.createApiKey(request.getHeader(), request.getUserId(),
                    request.getAccountType(), request.getIndex(), request.getAccountName(), request.getAccountId(),
                    request.getTag(), request.getType(), true);
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security createApiKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void updateApiKey(SecurityUpdateApiKeyRequest request, StreamObserver<SecurityUpdateApiKeyResponse> observer) {
        try {
            SecurityUpdateApiKeyResponse response = userApiKeyService.updateApiKey(request.getHeader(), request.getUserId(),
                    request.getApiKeyId(), request.getIpWhiteList(), request.getStatusValue(), request.getUpdateTypeValue());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security updateApiKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void getApiKey(SecurityGetApiKeyRequest request, StreamObserver<SecurityGetApiKeyResponse> observer) {
        try {
            SecurityGetApiKeyResponse response = userApiKeyService.getApiKey(request.getHeader(), request.getUserId(), request.getApiKeyId());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security getApiKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void queryUserApiKeys(SecurityQueryUserApiKeysRequest request, StreamObserver<SecurityQueryUserApiKeysResponse> observer) {
        try {
            SecurityQueryUserApiKeysResponse response = userApiKeyService.queryUserApiKeys(request.getHeader(), request.getHeader().getUserId());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security queryUserApiKeys error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void queryOrgAuthorizedAccountApiKeys(SecurityQueryOrgAuthorizedAccountApiKeysRequest request, StreamObserver<SecurityQueryUserApiKeysResponse> observer) {
        try {
            SecurityQueryUserApiKeysResponse response = userApiKeyService.queryUserApiKeysByAccountId(request.getHeader(), request.getHeader().getUserId(), request.getAccountId());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security queryOrgAuthorizedAccountApiKeys error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void validApiAccess(SecurityValidApiAccessRequest request, StreamObserver<SecurityValidApiAccessResponse> observer) {
        try {
            SecurityValidApiAccessResponse response = userApiKeyService.validApiRequest(request.getHeader(), request.getOriginStr(), request.getApiKey(),
                    request.getSignature(), request.getIsOrgApiRequest(), request.getForceCheckIpWhiteList());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security validApiAccess error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void deleteApiKey(SecurityDeleteApiKeyRequest request, StreamObserver<SecurityDeleteApiKeyResponse> observer) {
        try {
            SecurityDeleteApiKeyResponse response = userApiKeyService.deleteApiKey(request.getHeader(), request.getUserId(), request.getApiKeyId());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security deleteApiKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void validApiKey(SecurityValidApiKeyRequest request,
                            StreamObserver<SecurityValidApiKeyResponse> observer) {
        try {
            SecurityValidApiKeyResponse response = userApiKeyService.validApiKey(request.getHeader(), request.getApiKey());
            observer.onNext(response);
            observer.onCompleted();
        } catch (Exception e) {
            log.error("security validApiKey error", e);
            observer.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void setTradePassword(SecuritySetTradePasswordRequest request,
                                 StreamObserver<SecuritySetTradePasswordResponse> responseObserver) {
        try {
            SecuritySetTradePasswordResponse response = userSecurityService.setTradePassword(request.getHeader(),
                    request.getUserId(), request.getTradePassword());
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("security setTradePassword error", e);
            responseObserver.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void verifyTradePassword(SecurityVerifyTradePasswordRequest request,
                                    StreamObserver<SecurityVerifyTradePasswordResponse> responseObserver) {
        try {
            SecurityVerifyTradePasswordResponse response = userSecurityService.verifyTradePassword(request.getHeader(),
                    request.getUserId(), request.getTradePassword());
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("security verifyTradePassword error", e);
            responseObserver.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    //生成一个用户的token 目前给masker key 虚拟用户使用
    @Override
    public void queryUserToken(QueryUserTokenRequest request, StreamObserver<QueryUserTokenResponse> responseObserver) {
        try {
            String token = userSecurityService.getToken(request.getHeader(),
                    request.getUserId());
            responseObserver.onNext(QueryUserTokenResponse.newBuilder().setToken(token).build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("security verifyTradePassword error", e);
            responseObserver.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void alterBindGA(SecurityBindGARequest request, StreamObserver<SecurityBindGAResponse> responseObserver) {
        SecurityBindGAResponse response;
        try {
            response = userSecurityService.alterBindGA(request.getHeader(), request.getUserId(), request.getGaCode());
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (BrokerException e) {
            response = SecurityBindGAResponse.newBuilder().setRet(e.getCode()).build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("security rebindGA error", e);
            responseObserver.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }

    @Override
    public void changeUserApiLevel(ChangeUserApiLevelRequest request, StreamObserver<ChangeUserApiLevelResponse> responseObserver) {
        ChangeUserApiLevelResponse response;
        try {
            response = userApiKeyService.changeUserApiLevel(request.getOrgId(), request.getUserId(), Integer.parseInt(String.valueOf(request.getLevel())));
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (BrokerException e) {
            response = ChangeUserApiLevelResponse.newBuilder().setRet(e.getCode()).build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(new StatusRuntimeException(Status.UNKNOWN.withCause(e)));
        }
    }
}
