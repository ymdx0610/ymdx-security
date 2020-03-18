package com.ymdx.mapper;

import org.apache.ibatis.annotations.Select;
import com.ymdx.entity.UserEntity;

/**
 * @ClassName: UserMapper
 * @Description: TODO
 * @Author: com.ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:33
 * @Version: 1.0
 **/
public interface UserMapper {

    // ${} 容易产生sql注入
    @Select(" SELECT id,user_name as userName,password FROM user_info where user_name='${userName}' and password='${password}'")
//    @Select(" SELECT id,user_name as userName,password FROM user_info where user_name=#{userName} and password=#{password}")
    UserEntity findUser(UserEntity userEntity);

}
