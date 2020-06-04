package com.asquera.elasticsearch.plugins.http.security;

import java.util.Date;

import static org.elasticsearch.common.Strings.isEmpty;

/**
 * 
 * @description Token生成工具类
 */
public class TokenUtil {
    
    private static final EncryptUtil encryptUtil = new EncryptUtil();
    public static final String SPACE = " ";
    private static final int PAD_LIMIT = 8192;
    
	public static String genToken(){
		Date date = new Date();
		String str = date.getTime() + "" + ((Math.random() * 9 + 1) * 1000000);
		return str;
	}
	
	public static String genToken(String key) {
		try {
            String smpToken = key+"@"+genToken();
            String realKey = leftPad(key, 16, "*");
            String token = encryptUtil.encryptToAES(realKey, smpToken);
            return encryptUtil.encryptToMD5(key + "@" + encryptUtil.encryptToMD5(token));
        } catch (Exception e) {
		    e.printStackTrace();
        }
        return key;
	}
    public static String leftPad(final String str, final int size, String padStr) {
        if (str == null) {
            return null;
        }
        if (isEmpty(padStr)) {
            padStr = SPACE;
        }
        final int padLen = padStr.length();
        final int strLen = str.length();
        final int pads = size - strLen;
        if (pads <= 0) {
            return str; // returns original String when possible
        }
        if (padLen == 1 && pads <= PAD_LIMIT) {
            return leftPad(str, size, padStr.charAt(0));
        }

        if (pads == padLen) {
            return padStr.concat(str);
        } else if (pads < padLen) {
            return padStr.substring(0, pads).concat(str);
        } else {
            final char[] padding = new char[pads];
            final char[] padChars = padStr.toCharArray();
            for (int i = 0; i < pads; i++) {
                padding[i] = padChars[i % padLen];
            }
            return new String(padding).concat(str);
        }
    }
    public static String leftPad(final String str, final int size, final char padChar) {
        if (str == null) {
            return null;
        }
        final int pads = size - str.length();
        if (pads <= 0) {
            return str; // returns original String when possible
        }
        if (pads > PAD_LIMIT) {
            return leftPad(str, size, String.valueOf(padChar));
        }
        return repeat(padChar, pads).concat(str);
    }
    public static String repeat(final char ch, final int repeat) {
        final char[] buf = new char[repeat];
        for (int i = repeat - 1; i >= 0; i--) {
            buf[i] = ch;
        }
        return new String(buf);
    }
}
