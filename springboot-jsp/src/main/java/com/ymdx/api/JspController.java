package com.ymdx.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @ClassName: JspController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 16:17
 * @Version: 1.0
 **/
@Controller
public class JspController {

    @RequestMapping("/jspIndex")
    public String jspIndex() {
        return "jspIndex";
    }

}
