package com.ymdx.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassName: TokenFilter
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 14:25
 * @Version: 1.0
 **/
public class TokenFilter extends ZuulFilter {
    @Override
    public String filterType() {
        // 前置执行
        return "pre";
    }

    @Override
    public int filterOrder() {
        // 过滤器优先级：数字越大，越优先执行
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        // 是否开启当前filter
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        // 拦截参数执行业务逻辑
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String token = request.getParameter("token");
        if (StringUtils.isEmpty(token)) {
            // 直接不能够继续执行下面业务逻辑
            // 不继续执行下面业务逻辑
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(500);
            // 不继续执行下面业务逻辑
            ctx.setResponseBody("token is null");
            return null;
        }
        // 继续正常执行业务逻辑
        return null;
    }


}
