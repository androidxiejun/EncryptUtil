package com.dhht.encryptlibrary.internetutil;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * DES加密
 * @author Zhao XingLong
 */
public class DesUtils {
    /**
     * 向量
     */
    private final static String IV = "01234567";
    /**
     * 加密编码
     */
    private final static String ENCODING = "UTF-8";

    /**
     * 加密成3des
     *
     * @param plainText
     * @param decKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt3Des(String plainText, String decKey) throws Exception{
        //初始化向量
        IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
        //创建一个DESKeySpec对象
        DESedeKeySpec desKey = new DESedeKeySpec(decKey.getBytes());
        //创建一个密匙工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        //将DESKeySpec对象转换成SecretKey对象
        SecretKey secureKey = keyFactory.generateSecret(desKey);
        //Cipher对象实际实现解密操作
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        //用密匙初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, secureKey, ips);
        //真正开始加密操作
        return cipher.doFinal(plainText.getBytes(ENCODING));
    }

    /**
     * 加密成3des并且以BASE64字符串返回
     *
     * @param plainText 要加密的明码
     *      * @param decKey 密钥
     * @return 加密结果的BASE64字符串
     * @throws Exception
     */
    public static String encrypt3DesAsBase64(String plainText, String decKey) throws Exception {
        return Base64.encodeBase64String(encrypt3Des(plainText, decKey));
    }
}
