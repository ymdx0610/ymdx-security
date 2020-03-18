package com.ymdx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

/**
 * @ClassName: TokenApp
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 20:47
 * @Version: 1.0
 **/
@SpringBootApplication
@MapperScan(basePackages = { "com.ymdx.mapper" })
@ServletComponentScan
public class TokenApp {

    public static void main(String[] args) {
        SpringApplication.run(TokenApp.class, args);
    }

}
