package com.ymdx.api;

import com.ymdx.entity.UserEntity;
import com.ymdx.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: LoginController
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 10:38
 * @Version: 1.0
 **/
@RestController
public class LoginController {

    @Autowired
    private UserMapper userMapper;

    @RequestMapping("/login")
    public String login(UserEntity userEntity) {
        System.out.println("账号密码信息：userEntity:" + userEntity);
        UserEntity login = userMapper.findUser(userEntity);
        return login == null ? "登陆失败！" : "登陆成功！";
    }

}
