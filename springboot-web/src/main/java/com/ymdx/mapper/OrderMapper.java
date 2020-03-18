package com.ymdx.mapper;

import com.ymdx.entity.OrderEntity;
import org.apache.ibatis.annotations.Insert;

/**
 * @ClassName: OrderMapper
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 16:56
 * @Version: 1.0
 **/
public interface OrderMapper {

    @Insert("insert into order_info(order_code,order_desc) values (#{orderCode},#{orderDesc})")
    int addOrder(OrderEntity orderEntity);

}
