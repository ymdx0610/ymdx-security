package com.ymdx.entity;

import lombok.Data;

/**
 * @ClassName: AppEntity
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:20
 * @Version: 1.0
 **/
@Data
public class AppEntity {

    private Long id;
    private String appId;
    private String appName;
    private String appSecret;
    private String accessToken;
    private int status;

}
