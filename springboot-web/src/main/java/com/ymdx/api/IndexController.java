package com.ymdx.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassName: IndexController
 * @Description: TODO
 * @Author: com.ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:34
 * @Version: 1.0
 **/
@Controller
public class IndexController {

    /**
     * 跳转至index页面
     * @return
     */
    @RequestMapping("/index")
    public String index() {
        return "index";
    }

    /**
     * 接收页面参数
     * @param request
     * @return
     */
    @RequestMapping("/postIndex")
    public String postIndex(HttpServletRequest request) {
        request.setAttribute("name", request.getParameter("name"));
        return "forward";
    }

    /**
     * 跳转至上传文件页面
     * @return
     */
    @RequestMapping("/toUpload")
    public String toUpload() {
        return "uploadIndex";
    }

}
