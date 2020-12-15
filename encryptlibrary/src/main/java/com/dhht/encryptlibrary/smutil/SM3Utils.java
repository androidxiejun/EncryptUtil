package com.dhht.encryptlibrary.smutil;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.util.Arrays;

/**
 * SM3工具类
 *
 * @author zxl
 */
public class SM3Utils extends GMBaseUtils {

    /**
     * SM3杂凑运算
     *
     * @param srcData 要进行hash运算的数据
     * @return 32字节的hash数组
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * SM3杂凑运算
     *
     * @param srcStr 要进行hash运算的字符串
     * @return 32字节的hash数组
     */
    public static byte[] hash(String srcStr) {
        SM3Digest digest = new SM3Digest();
        byte[] srcData = srcStr.getBytes();
        return hash(srcData);
    }

    /**
     * SM3杂凑运算
     * @param srcData 要进行hash运算的数据
     * @return hash结果的16进制字符串
     */
    public static String hashHexStr(byte[] srcData) {
        return ByteUtils.toHexString(hash(srcData));
    }

    /**
     * SM3杂凑运算
     * @param srcStr 要进行hash运算的字符串
     * @return hash结果的16进制字符串
     */
    public static String hashHexStr(String srcStr) {
        return ByteUtils.toHexString(hash(srcStr));
    }

    /**
     * 校验数据的hash值
     * <p>
     * 对输入数据进行hash运算并与传入的hash值进行比较
     * </p>
     * @param srcData 要进行校验的数据
     * @param sm3Hash 期望的hash值
     * @return 校验结果
     */
    public static boolean verify(byte[] srcData, byte[] sm3Hash) {
        byte[] newHash = hash(srcData);
        if (Arrays.equals(newHash, sm3Hash)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 校验字符串的hash值
     * <p>
     * 对输入字符串进行hash运算并与传入的hash值进行比较
     * </p>
     * @param srcStr 要进行校验的字符串
     * @param sm3Hash 期望的hash值
     * @return 校验结果
     */
    public static boolean verify(String srcStr, byte[] sm3Hash) {
        byte[] srcData = srcStr.getBytes();
        return verify(srcData, sm3Hash);
    }

    /**
     * 校验字符串的hash值
     * <p>
     * 对输入字符串进行hash运算并与传入的hash值进行比较
     * </p>
     * @param srcStr 要进行校验的字符串
     * @param sm3HashHexStr 期望的hash值的16进制字符串
     * @return 校验结果
     */
    public static boolean verify(String srcStr, String sm3HashHexStr) {
        return verify(srcStr, ByteUtils.fromHexString(sm3HashHexStr));
    }

    public static byte[] hmac(byte[] key, byte[] srcData) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(srcData, 0, srcData.length);
        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }
}
