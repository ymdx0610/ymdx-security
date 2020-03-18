package com.ymdx.base;

import com.ymdx.utils.Constants;
import org.springframework.stereotype.Component;

/**
 * @ClassName: BaseApiController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:34
 * @Version: 1.0
 **/
@Component
public class BaseApiController {

    /**
     * 返回错误，可以传code和msg
     * @param code
     * @param msg
     * @return
     */
    public BaseResponse setResultError(Integer code, String msg) {
        return setResult(code, msg, null);
    }

    /**
     * 返回错误，可以传msg
     * @param msg
     * @return
     */
    public BaseResponse setResultError(String msg) {
        return setResult(Constants.HTTP_RES_CODE_500, msg, null);
    }

    /**
     * 返回成功，可以传data值
     * @param data
     * @return
     */
    public BaseResponse setResultSuccessData(Object data) {
        return setResult(Constants.HTTP_RES_CODE_200, Constants.HTTP_RES_CODE_200_VALUE, data);
    }

    public BaseResponse setResultSuccessData(Integer code, Object data) {
        return setResult(code, Constants.HTTP_RES_CODE_200_VALUE, data);
    }

    /**
     * 返回成功，沒有data值
     * @return
     */
    public BaseResponse setResultSuccess() {
        return setResult(Constants.HTTP_RES_CODE_200, Constants.HTTP_RES_CODE_200_VALUE, null);
    }

    /**
     * 返回成功，沒有data值
     * @param msg
     * @return
     */
    public BaseResponse setResultSuccess(String msg) {
        return setResult(Constants.HTTP_RES_CODE_200, msg, null);
    }

    /**
     * 通用封装
     * @param code
     * @param msg
     * @param data
     * @return
     */
    public BaseResponse setResult(Integer code, String msg, Object data) {
        return new BaseResponse(code, msg, data);
    }


}
