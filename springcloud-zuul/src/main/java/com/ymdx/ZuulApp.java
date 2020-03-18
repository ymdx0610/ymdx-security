package com.ymdx;

import com.ymdx.filter.TokenFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

/**
 * @ClassName: ZuulApp
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 14:24
 * @Version: 1.0
 **/
@SpringBootApplication
@EnableZuulProxy
@EnableEurekaClient
public class ZuulApp {

    public static void main(String[] args) {
        SpringApplication.run(ZuulApp.class, args);
    }

    /**
     * 注册到SpringBoot容器
     * @return
     */
    @Bean
    public TokenFilter accessFilter() {
        return new TokenFilter();
    }

}
