package com.ymdx.wrapper;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * @ClassName: XssHttpServletRequestWrapper
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:44
 * @Version: 1.0
 **/
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public XssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String getParameter(String name) {
        // 获取之前的参数
        String param = super.getParameter(name);
        System.out.println("原来参数：" + param);
        if (StringUtils.isNotEmpty(param)) {
            // 将特殊字符转换成html展示
            param = StringEscapeUtils.escapeHtml(param);
            System.out.println("转换后参数：" + param);
        }
        return param;
    }

}
