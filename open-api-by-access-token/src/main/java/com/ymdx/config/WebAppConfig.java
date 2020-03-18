package com.ymdx.config;

import com.ymdx.handler.AccessTokenInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @ClassName: WebAppConfig
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-16 00:09
 * @Version: 1.0
 **/
@Configuration
public class WebAppConfig {

    @Autowired
    private AccessTokenInterceptor accessTokenInterceptor;

    @Bean
    public WebMvcConfigurer WebMvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(accessTokenInterceptor).addPathPatterns("/open/api/*");
            }
        };
    }

}
