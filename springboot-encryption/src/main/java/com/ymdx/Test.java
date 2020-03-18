package com.ymdx;

import org.openjdk.jol.info.ClassLayout;

/**
 * @ClassName: Test
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-17 20:38
 * @Version: 1.0
 **/
public class Test {
    public static void main(String[] args) throws InterruptedException {
        // JVM启动后默认4s后，才开启偏向锁
        Thread.sleep(5000);

        Object o = new Object();
        System.out.println(ClassLayout.parseInstance(o).toPrintable());

        synchronized (o){
            System.out.println(ClassLayout.parseInstance(o).toPrintable());
        }
    }
}
