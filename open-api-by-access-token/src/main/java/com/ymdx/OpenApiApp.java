package com.ymdx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @ClassName: OpenApiApp
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:16
 * @Version: 1.0
 **/
@SpringBootApplication
@MapperScan(basePackages = "com.ymdx.mapper")
public class OpenApiApp {

    public static void main(String[] args) {
        SpringApplication.run(OpenApiApp.class, args);
    }

}
