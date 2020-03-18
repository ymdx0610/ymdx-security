package com.ymdx.aop;

import com.ymdx.annotation.ExtApiIdempotent;
import com.ymdx.annotation.ExtApiToken;
import com.ymdx.utils.ConstantUtils;
import com.ymdx.utils.RedisToken;
import org.apache.commons.lang.StringUtils;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @ClassName: ExtApiAopIdempotent
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-15 21:18
 * @Version: 1.0
 **/
@Aspect
@Component
public class ExtApiAopIdempotent {

    @Autowired
    private RedisToken redisToken;

    @Pointcut("execution(public * com.ymdx.api.*.*(..))")
    public void pointCut() {
    }

    @Before("pointCut()")
    public void before(JoinPoint point) {
        MethodSignature signature = (MethodSignature) point.getSignature();
        ExtApiToken extApiToken = signature.getMethod().getDeclaredAnnotation(ExtApiToken.class);
        if (extApiToken != null) {
            getRequest().setAttribute("token", redisToken.createToken());
        }
    }

    @Around("pointCut()")
    public Object around(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        // 判断方法上是否有加@ExtApiIdempotent注解
        MethodSignature methodSignature = (MethodSignature) proceedingJoinPoint.getSignature();
        ExtApiIdempotent declaredAnnotation = methodSignature.getMethod().getDeclaredAnnotation(ExtApiIdempotent.class);
        if (declaredAnnotation != null) {
            String type = declaredAnnotation.type();
            String token = null;
            HttpServletRequest request = getRequest();
            if (type.equals(ConstantUtils.EXTAPIHEAD)) {
                token = request.getHeader("token");
            } else {
                token = request.getParameter("token");
            }
            if (StringUtils.isEmpty(token)) {
                return "参数错误";
            }
            boolean existsToken = redisToken.findToken(token);
            if (!existsToken) {
                response("请勿重复提交!");
                return null;
            }
        }
        // 放行
        return proceedingJoinPoint.proceed();
    }

    private HttpServletRequest getRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        return request;
    }

    private void response(String msg) throws IOException {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletResponse response = attributes.getResponse();
        response.setHeader("Content-type", "text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        try {
            writer.println(msg);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            writer.close();
        }
    }

}
