package com.ymdx.utils;

import org.apache.commons.lang.StringUtils;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @ClassName: TokenUtils
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 17:27
 * @Version: 1.0
 **/
public class TokenUtils {

    private static Map<String, Object> tokenMap = new ConcurrentHashMap<String, Object>();

    /**
     * 创建token并暂存到tokenMap中
     * @return
     */
    public static synchronized String createToken() {
        // 如何在分布式场景下使用？通过分布式全局ID实现
        String token = "token-" + UUID.randomUUID();
        // hashMap好处可以附带附加信息
        tokenMap.put(token, token);
        return token;
    }

    /**
     * 判断token在缓存中是否存在
     * @param tokenKey
     * @return
     */
    public static boolean findToken(String tokenKey) {
        // 判断该令牌是否在tokenMap 是否存在
        String token = (String) tokenMap.get(tokenKey);
        if (StringUtils.isEmpty(token)) {
            return false;
        }
        // token获取成功后，需要删除
        tokenMap.remove(token);
        return true;
    }

}
