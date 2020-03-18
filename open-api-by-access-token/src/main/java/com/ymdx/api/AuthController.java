package com.ymdx.api;

import com.alibaba.fastjson.JSONObject;
import com.ymdx.base.BaseApiController;
import com.ymdx.base.BaseRedisService;
import com.ymdx.base.BaseResponse;
import com.ymdx.entity.AppEntity;
import com.ymdx.mapper.AppMapper;
import com.ymdx.utils.Constants;
import com.ymdx.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: AuthController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:49
 * @Version: 1.0
 **/
@RestController
@RequestMapping(value = "/auth")
public class AuthController extends BaseApiController {

    @Autowired
    private BaseRedisService baseRedisService;

    @Autowired
    private AppMapper appMapper;

    /**
     * 使用 appId + appSecret 生成 accessToke
     * @param appEntity
     * @return
     */
    @RequestMapping("/getAccessToken")
    public BaseResponse getAccessToken(AppEntity appEntity) {
        AppEntity appResult = appMapper.findApp(appEntity);
        if (appResult == null) {
            return setResultError("没有对应机构的认证信息");
        }
        int status = appResult.getStatus();
        if (status == 1) {
            return setResultError("您现在没有权限生成对应的AccessToken");
        }
        // 获取新的accessToken之前删除原来的accessToken
        // 从redis中删除原来的的accessToken
        String accessToken = appResult.getAccessToken();
        baseRedisService.delKey(accessToken);
        // 生成的新的accessToken
        String newAccessToken = newAccessToken(appResult.getAppId());
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("accessToken", newAccessToken);
        return setResultSuccessData(jsonObject);
    }

    private String newAccessToken(String appId) {
        // 使用 appId + appSecret 生成对应的 accessToken，暂存2个小时
        String accessToken = TokenUtils.getAccessToken();

        // 保证在同一个事务中
        // 生成最新的token：key为accessToken，value为appId
        baseRedisService.setString(accessToken, appId, Constants.TOKEN_TIMEOUT);
        // 将表中更新为当前的accessToken
        appMapper.updateAccessToken(accessToken, appId);
        return accessToken;
    }

}
