package com.ymdx.mapper;

import com.ymdx.entity.AppEntity;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

/**
 * @ClassName: AppMapper
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 23:22
 * @Version: 1.0
 **/
public interface AppMapper {

    @Select("select id,app_id as appId,app_name as appName,app_secret as appSecret,access_token as accessToken,`status` from app_info where app_id=#{appId} and app_secret=#{appSecret} ")
    AppEntity findApp(AppEntity appEntity);

    @Select("select id,app_id as appId,app_name as appName,app_secret as appSecret,access_token as accessToken,`status` from app_info where app_id=#{appId} ")
    AppEntity findByAppId(@Param("appId") String appId);

    @Update("update app_info set access_token=#{accessToken} where app_id=#{appId} ")
    int updateAccessToken(@Param("accessToken") String accessToken, @Param("appId") String appId);

}
