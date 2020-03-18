package com.ymdx.filter;

import com.ymdx.wrapper.XssHttpServletRequestWrapper;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * @ClassName: XssFilter
 * @Description: 防止XSS攻击
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:40
 * @Version: 1.0
 **/
@WebFilter(filterName = "xssFilter", urlPatterns = "/*")
public class XssFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        // 使用拦截器拦截所有请求
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        // 重写getParameter方法
        XssHttpServletRequestWrapper xssHttpServletRequestWrapper = new XssHttpServletRequestWrapper(req);
        // 放行程序，继续往下执行
        filterChain.doFilter(xssHttpServletRequestWrapper, servletResponse);
    }

}
