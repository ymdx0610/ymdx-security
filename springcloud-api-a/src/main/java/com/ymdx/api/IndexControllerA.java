package com.ymdx.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: IndexControllerA
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 14:18
 * @Version: 1.0
 **/
@SpringBootApplication
@EnableDiscoveryClient
@RestController
public class IndexControllerA {
    @RequestMapping("/")
    public String index() {
        return "This is api-a....";
    }

    public static void main(String[] args) {
        SpringApplication.run(IndexControllerA.class, args);
    }
}
