package com.ymdx.rsa;

import javax.crypto.Cipher;

/**
 * @ClassName: Test001
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 10:55
 * @Version: 1.0
 **/
public class Test001 {

    public static void main(String[] args) {
        // 实现步骤：
        // 1.生成公钥和私钥密钥对
        RSAUtil.generateKey();
        System.out.println("私钥：" + RSAUtil.privateKey);
        System.out.println("公钥：" + RSAUtil.publicKey);
        String content = "ymdx";
        // 2.使用公钥进行加密
        String encryptByPublicKey = RSAUtil.encryptByPublicKey(content, RSAUtil.publicKey, Cipher.ENCRYPT_MODE);
        System.out.println("加密后：" + encryptByPublicKey);
        String encryptByprivateKey = RSAUtil.encryptByprivateKey(encryptByPublicKey, RSAUtil.privateKey, Cipher.DECRYPT_MODE);
        // 3.使用私钥进行解密
        System.out.println("解密后：" + encryptByprivateKey);

        // 在实际在开发中，后端开发人员生成好密钥对，服务器端保存私钥，客户端保存公钥
    }
}
