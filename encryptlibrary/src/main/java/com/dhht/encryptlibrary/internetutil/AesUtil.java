package com.dhht.encryptlibrary.internetutil;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author xyuxiao
 * @date 2017/1/4
 */
public class AesUtil {

    /**
     * 加密
     *
     * @param key     密钥
     * @param content 明文字符串
     * @return 密文的base64编码
     */
    public static String encrypt(String key, String content) {
        try {
            byte[] rawKey = getRawKey(key.getBytes());
            SecretKeySpec secretKeySpec = new SecretKeySpec(rawKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encypted = cipher.doFinal(content.getBytes("UTF-8"));
            return Base64.encodeBase64String(encypted);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 解密
     *
     * @param base64Content 密文的base64编码
     * @param key     密钥
     * @return 解密后的字符串
     */
    public static String decrypt(String key, String base64Content) {
        try {
            byte[] rawKey = getRawKey(key.getBytes());
            byte[] encrypted = Base64.decodeBase64(base64Content);
            SecretKeySpec secretKeySpec = new SecretKeySpec(rawKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decrypted = cipher.doFinal(encrypted);
            String string = new String(decrypted, "UTF-8");
            return string;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * @param seed 种子数据
     * @return 密钥数据
     */
    private static byte[] getRawKey(byte[] seed) {
        byte[] rawKey = null;
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            // AES加密数据块分组长度必须为128比特，密钥长度可以是128比特、192比特、256比特中的任意一个
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            rawKey = secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
        }
        return rawKey;
    }
}

