package com.ymdx.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;

/**
 * @ClassName: WeiXinUtils
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-16 13:29
 * @Version: 1.0
 **/
@Component
public class WeiXinUtils {
    @Value("${appid}")
    private String appId;
    @Value("${secret}")
    private String secret;
    @Value("${redirecturi}")
    private String redirectUri;
    @Value("${authorizedUrl}")
    private String authorizedUrl;
    @Value("${access_token}")
    private String accessToken;
    @Value("${userinfo}")
    private String userinfo;

    public String getAuthorizedUrl() {
        return authorizedUrl.replace("APPID", appId).replace("REDIRECT_URI", URLEncoder.encode(redirectUri));
    }

    public String getAccessTokenUrl(String code) {
        return accessToken.replace("APPID", appId).replace("SECRET", secret).replace("CODE", code);
    }

    public String getUserInfo(String accessToken, String openId) {
        return userinfo.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openId);
    }

}
