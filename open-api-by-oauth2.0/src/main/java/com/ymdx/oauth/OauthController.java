package com.ymdx.oauth;

import com.alibaba.fastjson.JSONObject;
import com.ymdx.utils.Constants;
import com.ymdx.utils.HttpClientUtils;
import com.ymdx.utils.WeiXinUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassName: OauthController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-16 13:28
 * @Version: 1.0
 **/
@Controller
@Slf4j
public class OauthController {

    @Autowired
    private WeiXinUtils weiXinUtils;

    @GetMapping("/index")
    @ResponseBody
    public String index() {
        return "Hello World!";
    }

    /**
     * 生成授权链接
     *
     * http://ymdx.natapp1.cc/authorizedUrl
     *
     * @return
     */
    @GetMapping("/authorizedUrl")
    public String authorizedUrl() {
        return "redirect:" + weiXinUtils.getAuthorizedUrl();
    }

    /**
     * 微信授权回调地址
     *
     * @param code
     * @param request
     * @return
     */
    @RequestMapping("/callback")
    public String callback(String code, HttpServletRequest request) {
        // 1. 使用code获取access_token
        String accessTokenUrl = weiXinUtils.getAccessTokenUrl(code);
        log.info("accessTokenUrl -> {}", accessTokenUrl);
        JSONObject resultAccessToken = HttpClientUtils.httpGet(accessTokenUrl);
        boolean containsKey = resultAccessToken.containsKey("errcode");
        if (containsKey) {
            request.setAttribute("errorMsg", "认证失败！");
            return Constants.HTTP_RES_CODE_500_VALUE;
        }
        // 2. 使用access_token获取用户信息
        String accessToken = resultAccessToken.getString("access_token");
        String openid = resultAccessToken.getString("openid");
        // 3. 获取用户信息(需scope为snsapi_userinfo)
        String userInfoUrl = weiXinUtils.getUserInfo(accessToken, openid);
        log.info("userInfoUrl -> {}", userInfoUrl);
        JSONObject userInfoResult = HttpClientUtils.httpGet(userInfoUrl);
        System.out.println("userInfoResult:" + userInfoResult);
        log.info("userInfoResult -> {}", userInfoResult);
        request.setAttribute("nickname", userInfoResult.getString("nickname"));
        request.setAttribute("city", userInfoResult.getString("city"));
        request.setAttribute("headimgurl", userInfoResult.getString("headimgurl"));
        return "info";
    }

}
