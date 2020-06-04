package com.asquera.elasticsearch.plugins.http.security;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 *
 */
public class EncryptUtil {
    /**
     * @param info
     */
    public String encryptToMD5(String info) {
        byte[] digesta = null;
        try {
            // 得到一个md5的消息摘要
            MessageDigest alga = MessageDigest.getInstance("MD5");
            // 添加要进行计算摘要的信息
            alga.update(info.getBytes());
            // 得到该摘要
            digesta = alga.digest();
        } catch (NoSuchAlgorithmException e) {
            e.getMessage();
        }
        // 将摘要转为字符串
        String rs = byte2hex(digesta);
        return rs;
    }

    /**
     * @param info
     */
    public String encryptToSHA(String info) throws Exception {
        byte[] digesta = null;
        try {
            // 得到一个SHA-1的消息摘要
            MessageDigest alga = MessageDigest.getInstance("SHA-1");
            // 添加要进行计算摘要的信息
            alga.update(info.getBytes());
            // 得到该摘要
            digesta = alga.digest();
        } catch (NoSuchAlgorithmException e) {
            throw e;
        }
        // 将摘要转为字符串
        String rs = byte2hex(digesta);
        return rs;
    }

    /**
     * @param algorithm
     * @param src
     */
    public String getKey(String algorithm, String src) {
        if (algorithm.equals("AES")) {
            return src.substring(0, 16);
        } else if (algorithm.equals("DES")) {
            return src.substring(0, 8);
        } else {
            return null;
        }
    }

    /**
     * @param src
     */
    public String getAESKey(String src) {
        return this.getKey("AES", src);
    }

    /**
     * @param src
     */
    public String getDESKey(String src) {
        return this.getKey("DES", src);
    }

    /**
     * @param algorithm 加密算法,可用 AES,DES,DESede,Blowfish
     */
    public SecretKey createSecretKey(String algorithm) {
        // 声明KeyGenerator对象
        KeyGenerator keygen;
        // 声明 密钥对象
        SecretKey deskey = null;
        try {
            // 返回生成指定算法的秘密密钥的 KeyGenerator 对象
            keygen = KeyGenerator.getInstance(algorithm);
            // 生成一个密钥
            deskey = keygen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.getMessage();
        }
        // 返回密匙
        return deskey;
    }

    /**
     *
     */
    public SecretKey createSecretAESKey() {
        return createSecretKey("AES");
    }

    /**
     *
     */
    public SecretKey createSecretDESKey() {
        return createSecretKey("DES");
    }

    /**
     * @param Algorithm 加密算法:DES,AES
     * @param key
     * @param info
     */
    public String encrypt(String Algorithm, SecretKey key, String info) {
        // 定义要生成的密文
        byte[] cipherByte = null;
        try {
            // 得到加密/解密器
            Cipher c1 = Cipher.getInstance(Algorithm);
            // 用指定的密钥和模式初始化Cipher对象
            // 参数:(ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE,UNWRAP_MODE)
            c1.init(Cipher.ENCRYPT_MODE, key);
            // 对要加密的内容进行编码处理,
            cipherByte = c1.doFinal(info.getBytes());
        } catch (Exception e) {
            e.getMessage();
        }
        // 返回密文的十六进制形式
        return byte2hex(cipherByte);
    }

    /**
     * @param Algorithm
     * @param key
     * @param sInfo
     */
    public String decrypt(String Algorithm, SecretKey key, String sInfo) {
        byte[] cipherByte = null;
        try {
            // 得到加密/解密器
            Cipher c1 = Cipher.getInstance(Algorithm);
            // 用指定的密钥和模式初始化Cipher对象
            c1.init(Cipher.DECRYPT_MODE, key);
            // 对要解密的内容进行编码处理
            cipherByte = c1.doFinal(hex2byte(sInfo));
        } catch (Exception e) {
            e.getMessage();
        }
        return new String(cipherByte);
    }

    /**
     * @param Algorithm 加密算法:DES,AES
     * @param key       这个key可以由用户自己指定 注意AES的长度为16位,DES的长度为8位
     * @param sInfo
     */
    public static String decrypt(String Algorithm, String sSrc, String sKey)
            throws Exception {
        try {
            // 判断Key是否正确
            if (sKey == null) {
                throw new Exception("Key为空null");
            }
            // 判断采用AES加解密方式的Key是否为16位
            if (Algorithm.equals("AES") && sKey.length() != 16) {
                throw new Exception("Key长度不是16位");
            }
            // 判断采用DES加解密方式的Key是否为8位
            if (Algorithm.equals("DES") && sKey.length() != 8) {
                throw new Exception("Key长度不是8位");
            }
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, Algorithm);
            Cipher cipher = Cipher.getInstance(Algorithm);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] encrypted1 = hex2byte(sSrc);
            try {
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original);
                return originalString;
            } catch (Exception e) {
                throw new Exception(e.getMessage());
            }
        } catch (Exception ex) {
            throw new Exception(ex.getMessage());
        }
    }

    /**
     * @param Algorithm 加密算法:DES,AES
     * @param key       这个key可以由用户自己指定 注意AES的长度为16位,DES的长度为8位
     * @param info
     */
    public static String encrypt(String Algorithm, String sSrc, String sKey)
            throws Exception {
        // 判断Key是否正确
        if (sKey == null) {
            throw new Exception("Key为空null");
        }
        // 判断采用AES加解密方式的Key是否为16位
        if (Algorithm.equals("AES") && sKey.length() != 16) {
            throw new Exception("Key长度不是16位");
        }
        // 判断采用DES加解密方式的Key是否为8位
        if (Algorithm.equals("DES") && sKey.length() != 8) {
            throw new Exception("Key长度不是8位");
        }
        byte[] raw = sKey.getBytes("ASCII");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, Algorithm);
        Cipher cipher = Cipher.getInstance(Algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes());
        return byte2hex(encrypted);
    }

    /**
     * @param key
     * @param info
     */
    public String encryptToDES(SecretKey key, String info) {
        return encrypt("DES", key, info);
    }

    /**
     * @param key
     * @param info
     */
    public String encryptToDES(String key, String info)
            throws Exception {
        return encrypt("DES", info, key);
    }

    /**
     * @param key
     * @param sInfo
     */
    public String decryptByDES(SecretKey key, String sInfo) {
        return decrypt("DES", key, sInfo);
    }

    /**
     * @param key
     * @param sInfo
     */
    public String decryptByDES(String key, String sInfo)
            throws Exception {
        return decrypt("DES", sInfo, key);
    }

    /**
     * @param key
     * @param info
     */
    public String encryptToAES(SecretKey key, String info) {
        return encrypt("AES", key, info);
    }

    /**
     * @param key
     * @param info
     */
    public String encryptToAES(String key, String info)
            throws Exception {
        return encrypt("AES", info, key);
    }

    /**
     * @param key
     * @param sInfo
     */
    public String decryptByAES(SecretKey key, String sInfo) {
        return decrypt("AES", key, sInfo);
    }

    /**
     * @param key
     * @param sInfo
     */
    public String decryptByAES(String key, String sInfo)
            throws Exception {
        return decrypt("AES", sInfo, key);
    }

    /**
     * @param hex
     */
    public static byte[] hex2byte(String strhex) {
        if (strhex == null) {
            return null;
        }
        int l = strhex.length();
        if (l % 2 == 1) {
            return null;
        }
        byte[] b = new byte[l / 2];
        for (int i = 0; i != l / 2; i++) {
            b[i] = (byte) Integer.parseInt(strhex.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    /**
     * @param b 二进制字节数组
     * @return String
     */
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }
}
