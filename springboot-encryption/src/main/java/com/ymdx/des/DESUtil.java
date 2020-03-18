package com.ymdx.des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;

/**
 * @ClassName: DESUtil
 * @Description:
 *
 * DES加密介绍：
 * DES是一种对称加密算法，所谓对称加密算法，即：加密和解密使用相同密钥的算法。
 * DES加密算法出自IBM的研究，后来被美国政府正式采用，之后开始广泛流传，但是近些年使用越来越少，因为DES使用56位密钥，以现代计算能力，24小时内即可被破解。
 * 虽然如此，在某些简单应用中，我们还是可以使用DES加密算法，本文简单讲解DES的JAVA实现 。
 * 注意：DES加密和解密过程中，密钥长度都必须是8的倍数
 *
 * @Author: ymdx
 * @Email: y_m_d_x@163.com
 * @Date: 2020-03-18 10:40
 * @Version: 1.0
 **/
public class DESUtil {

    public DESUtil() {
    }

    /**
     * 测试
     * @param args
     * @throws Exception
     */
    public static void main(String args[]) throws Exception {
        // 待加密内容
        String str = "ymdx";
        // 密码，长度要是8的倍数，密钥随意定
        String password = "12345678";
        byte[] encrypt = encrypt(str.getBytes(), password);
        System.out.println("加密后:" + new String(encrypt));
        // 解密
        byte[] decrypt = decrypt(encrypt, password);
        System.out.println("解密后:" + new String(decrypt));
    }

    /**
     * 加密
     * @param datasource
     * @param password
     * @return
     */
    public static byte[] encrypt(byte[] datasource, String password) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(password.getBytes());
            // 创建一个密匙工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESUtil");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DESUtil");
            // 用密匙初始化Cipher对象，ENCRYPT_MODE用于将Cipher初始化为加密模式的常量
            cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
            // 获取数据并加密，正式执行加密操作
            // 按单部分操作加密或解密数据，或者结束一个多部分操作
            return cipher.doFinal(datasource);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     * @param src
     * @param password
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] src, String password) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom random = new SecureRandom();
        // 创建一个DESKeySpec对象
        DESKeySpec desKey = new DESKeySpec(password.getBytes());
        // 创建一个密匙工厂，返回实现指定转换的
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESUtil");
        // Cipher对象，将DESKeySpec对象转换成SecretKey对象
        SecretKey securekey = keyFactory.generateSecret(desKey);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance("DESUtil");
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, random);
        // 真正开始解密操作
        return cipher.doFinal(src);
    }

}
