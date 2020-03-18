package com.ymdx.handler;

import com.alibaba.fastjson.JSONObject;
import com.ymdx.base.BaseApiController;
import com.ymdx.base.BaseRedisService;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @ClassName: AccessTokenInterceptor
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-16 00:02
 * @Version: 1.0
 **/
@Component
public class AccessTokenInterceptor extends BaseApiController implements HandlerInterceptor {

    @Autowired
    private BaseRedisService baseRedisService;

    /**
     * 进入controller层之前拦截请求
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @param obj
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object obj)
            throws Exception {
        System.out.println("--------------开始进入请求地址拦截--------------");
        String accessToken = httpServletRequest.getParameter("accessToken");
        // 判断accessToken是否为空
        if (StringUtils.isEmpty(accessToken)) {
            // 参数Token accessToken
            resultError("accessToken is null", httpServletResponse);
            return false;
        }
        String appId = (String) baseRedisService.getString(accessToken);
        if (StringUtils.isEmpty(appId)) {
            // accessToken 已经失效!
            resultError("accessToken is invalid", httpServletResponse);
            return false;
        }
        // 正常执行业务逻辑...
        return true;

    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o,
                           ModelAndView modelAndView) throws Exception {
        System.out.println("--------------处理请求完成后视图渲染之前的处理操作--------------");
    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                Object o, Exception e) throws Exception {
        System.out.println("--------------视图渲染之后的操作--------------");
    }

    /**
     * 返回错误提示
     * @param errorMsg
     * @param httpServletResponse
     * @throws IOException
     */
    public void resultError(String errorMsg, HttpServletResponse httpServletResponse) throws IOException {
        PrintWriter printWriter = httpServletResponse.getWriter();
        printWriter.write(JSONObject.toJSONString(setResultError(errorMsg)));
    }

}
