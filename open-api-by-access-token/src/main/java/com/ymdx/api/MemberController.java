package com.ymdx.api;

import com.ymdx.base.BaseApiController;
import com.ymdx.base.BaseResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: MemberController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-16 00:12
 * @Version: 1.0
 **/
@RestController
@RequestMapping("/open/api")
public class MemberController extends BaseApiController {

    @GetMapping("/getMember")
    public BaseResponse getMember() {
        return setResultSuccess("获取会员信息接口");
    }

}
