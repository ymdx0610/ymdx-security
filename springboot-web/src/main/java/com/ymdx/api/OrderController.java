package com.ymdx.api;

import com.ymdx.entity.OrderEntity;
import com.ymdx.mapper.OrderMapper;
import com.ymdx.utils.TokenUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassName: OrderController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 16:58
 * @Version: 1.0
 **/
@RestController
public class OrderController {

    @Autowired
    private OrderMapper orderMapper;

    @GetMapping("/getToken")
    public String getToken() {
        return TokenUtils.createToken();
    }

    @PostMapping(value = "/addOrder", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public String addOrder(@RequestBody OrderEntity orderEntity, HttpServletRequest request) {

        // 1.什么Token（令牌），表示是一个临时且不允许重复的值（临时且唯一）
        // 2.使用令牌方式防止Token重复提交

        // 使用场景：在调用API接口的时，需要传递令牌，该API接口获取到令牌之后，执行当前业务逻辑，然后把当前的令牌删除掉。
        // 在调用第API接口的时候，需要传递令牌，建议有效时间为15mi至2h
        // 代码步骤：
        // 1.获取令牌
        // 2.判断令牌是否在缓存中有对应的数据
        // 3.如何缓存中没有该令牌，直接报错（请勿重复提交）
        // 4.如何缓存有该令牌，直接执行该业务逻辑
        // 5.执行完业务逻辑之后，删除该令牌

        String token = request.getHeader("token");
        if (StringUtils.isEmpty(token)) {
            return "参数错误！";
        }

        if (!TokenUtils.findToken(token)) {
            return "请勿重复提交！";
        }

        int result = orderMapper.addOrder(orderEntity);
        return result > 0 ? "添加成功！" : "添加失败！" + "";
    }

}
