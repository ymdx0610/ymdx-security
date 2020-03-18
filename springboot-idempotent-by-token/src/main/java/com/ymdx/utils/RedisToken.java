package com.ymdx.utils;

import com.ymdx.base.BaseRedisService;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * @ClassName: RedisToken
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 20:53
 * @Version: 1.0
 **/
@Component
public class RedisToken {

    @Autowired
    private BaseRedisService baseRedisService;

    private static final long TOKENTIMEOUT = 60 * 60;

    public String createToken() {
        // token保证临时且唯一
        // 如何在分布式场景下使用？通过分布式全局ID实现
        String token = "token-" + UUID.randomUUID();
        // 如何保证token临时？使用redis缓存
        baseRedisService.setString(token, token, TOKENTIMEOUT);
        return token;
    }

    public synchronized boolean findToken(String tokenKey) {
        // 接口获取对应的令牌，如果能够获取到该令牌，就直接执行后续的业务逻辑
        String tokenValue = (String) baseRedisService.getString(tokenKey);
        if (StringUtils.isEmpty(tokenValue)) {
            return false;
        }
        // 保证每个接口对应的token只能被访问一次，保证接口幂等性
        baseRedisService.delKey(tokenValue);
        return true;
    }

}
