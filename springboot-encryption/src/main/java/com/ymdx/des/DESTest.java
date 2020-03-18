package com.ymdx.des;

/**
 * @ClassName: DESTest
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 11:13
 * @Version: 1.0
 **/
public class DESTest {

    // 1.配置密钥
    private static String PASSWORD = "66778899";

    public static void main(String[] args) throws Exception {
        // 2.需要加密的内容
        String content = "ymdx";
        // 3.使用DES加密
        byte[] encryptContent = DESUtil.encrypt(content.getBytes(), PASSWORD);
        System.out.println("加密后内容:" + new String(encryptContent));
        // 4.使用DES解密
        byte[] decrypt = DESUtil.decrypt(encryptContent, PASSWORD);
        System.out.println("解密后内容:" + new String(decrypt));
    }

}
