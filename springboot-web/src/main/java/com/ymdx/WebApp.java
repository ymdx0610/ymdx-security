package com.ymdx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

/**
 * @ClassName: App
 * @Description: TODO
 * @Author: com.ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:06
 * @Version: 1.0
 **/
@SpringBootApplication
@MapperScan(basePackages = { "com.ymdx.mapper" })
@ServletComponentScan
public class WebApp {

    public static void main(String[] args) {
        SpringApplication.run(WebApp.class, args);
    }

}
