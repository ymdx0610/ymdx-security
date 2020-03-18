package com.ymdx.api;

import com.ymdx.annotation.ExtApiIdempotent;
import com.ymdx.annotation.ExtApiToken;
import com.ymdx.entity.OrderEntity;
import com.ymdx.mapper.OrderMapper;
import com.ymdx.utils.ConstantUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @ClassName: OrderPageController
 * @Description: TODO
 * @Author: com.ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:34
 * @Version: 1.0
 **/
@Controller
public class OrderPageController {
    @Autowired
    private OrderMapper orderMapper;

    /**
     * 跳转至index页面
     *
     * @return
     */
    @RequestMapping("/index")
    @ExtApiToken
    public String indexPage() {
        return "index";
    }

    @RequestMapping("/addOrderByForm")
    @ExtApiIdempotent(type = ConstantUtils.EXTAPIFROM)
    public String addOrderByForm(OrderEntity orderEntity) {
        int addOrder = orderMapper.addOrder(orderEntity);
        return addOrder > 0 ? "success" : "fail";
    }

}