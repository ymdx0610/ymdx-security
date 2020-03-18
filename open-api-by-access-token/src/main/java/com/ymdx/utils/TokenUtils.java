package com.ymdx.utils;

import org.springframework.web.bind.annotation.GetMapping;

import java.util.UUID;

/**
 * @ClassName: TokenUtils
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:57
 * @Version: 1.0
 **/
public class TokenUtils {

    @GetMapping("/getToken")
    public static String getAccessToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}
