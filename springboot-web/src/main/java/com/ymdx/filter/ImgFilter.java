package com.ymdx.filter;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * @ClassName: ImgFilter
 * @Description: 图片防盗链
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 16:45
 * @Version: 1.0
 **/
@WebFilter(filterName = "imgFilter", urlPatterns = "/imgs/*")
public class ImgFilter implements Filter {

    @Value("${domain.name}")
    private String domainName;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        // 1.获取请求头中的来源字段
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        String referer = req.getHeader("Referer");
        if (StringUtils.isEmpty(referer)) {
            req.getRequestDispatcher("/imgs/error.png").forward(req, servletResponse);
            return;
        }
        // 2.判断请求头中的域名是否和限制的域名一致
        String domainUrl = getDomain(referer);
        // 正常通过黑名单/白名单接口过滤
        if (!domainUrl.equals(domainName)) {
            req.getRequestDispatcher("/imgs/error.png").forward(req, servletResponse);
            return;
        }
        // 直接放行，继续之后的操作
        filterChain.doFilter(req, servletResponse);
    }

    private String getDomain(String url) {
        String result = "";
        int j = 0, startIndex = 0, endIndex = 0;
        for (int i = 0; i < url.length(); i++) {
            if (url.charAt(i) == '/') {
                j++;
                if (j == 2)
                    startIndex = i;
                else if (j == 3)
                    endIndex = i;
            }

        }
        result = url.substring(startIndex + 1, endIndex);
        return result;
    }

}
