package com.ymdx.base;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

/**
 * @ClassName: BaseResponse
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:37
 * @Version: 1.0
 **/
@Getter
@Setter
@ToString
@Slf4j
public class BaseResponse {

    private Integer code;
    private String msg;
    private Object data;

    public BaseResponse() {
    }

    public BaseResponse(Integer code, String msg, Object data) {
        super();
        this.code = code;
        this.msg = msg;
        this.data = data;
    }


}
