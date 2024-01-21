/**********************************
 *@项目名称: security-parent
 *@文件名称: io.bhex.broker.security.service
 *@Date 2018/10/18
 *@Author peiwei.ren@bhex.io 
 *@Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 *注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的。
 ***************************************/
package io.bhex.broker.security.service;

import io.bhex.broker.security.service.entity.VerifyCode;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class InternalService {

    @Resource
    private VerifyCodeMapper verifyCodeMapper;

    public VerifyCode getVerifyCode(Long id) {
        return verifyCodeMapper.get(id);
    }

    public List<VerifyCode> queryVerifyCode(String receiver) {
        return verifyCodeMapper.queryByReceiver(receiver);
    }

}
