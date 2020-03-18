package com.ymdx.rsa;

import javax.crypto.Cipher;

/**
 * @ClassName: Test002
 * @Description: TODO
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 10:56
 * @Version: 1.0
 **/
public class Test002 {

    public static void main(String[] args) {
        // 1.生成（公钥和私钥）密钥对
        RSAUtil.generateKey();
        System.out.println("公钥：" + RSAUtil.publicKey);
        System.out.println("私钥：" + RSAUtil.privateKey);
        System.out.println("----------公钥加密私钥解密-------------");
        // 2.使用公钥加密,私钥解密
        String textsr = "ymdx";
        String encryptByPublic = RSAUtil.encryptByPublicKey(textsr, RSAUtil.publicKey, Cipher.ENCRYPT_MODE);
        System.out.println("公钥加密：" + encryptByPublic);
        String text = RSAUtil.encryptByprivateKey(encryptByPublic, RSAUtil.privateKey, Cipher.DECRYPT_MODE);
        System.out.print("私钥解密：" + text);
    }

}
