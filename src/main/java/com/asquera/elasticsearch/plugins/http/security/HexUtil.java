package com.asquera.elasticsearch.plugins.http.security;

/**
 * 
 * @description Hex处理工具类
 * @date 2016年9月30日下午5:22:59
 */
public class HexUtil {

    private HexUtil() {
    }

    /**
     * 
     * @description byte array 转为 hex string.
     * @param b byte数组
     * @return Hex字符串
     * @date 2016年9月30日下午5:23:34
     */
    public static String toHexString(byte[] b) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            sb.append(HexUtil.HEX_CHARS.charAt(b[i] >>> 4 & 0x0F));
            sb.append(HexUtil.HEX_CHARS.charAt(b[i] & 0x0F));
        }
        return sb.toString();
    }

    /**
     * 
     * @description hex string 转为  byte array
     * @param s Hex字符串
     * @return byte数组
     * @date 2016年9月30日下午5:23:34
     */
    public static byte[] toByteArray(String s) {
        byte[] buf = new byte[s.length() / 2];
        int j = 0;
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) ((Character.digit(s.charAt(j++), 16) << 4) | Character
                    .digit(s.charAt(j++), 16));
        }
        return buf;
    }

    private static final String HEX_CHARS = "0123456789abcdef";

}
