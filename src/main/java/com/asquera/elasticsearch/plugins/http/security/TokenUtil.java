package com.asquera.elasticsearch.plugins.http.security;

import com.asquera.elasticsearch.plugins.http.HttpBasicLogger;
import com.asquera.elasticsearch.plugins.http.auth.Authenticator;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
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

    /**
     * @param uri
     * @param name
     * @param value
     * @return True iff the token valid
     */
    public static boolean tokenService(String uri, String name, String value) {
        URL url;
        HttpURLConnection httpConnection;
        int returnCode;
        try {
            String params = "?" + name + "=" + value;
            url = new URL(uri + params);
            httpConnection = (HttpURLConnection) url.openConnection();
            httpConnection.setRequestMethod("GET");// 设置请求方式
            httpConnection.setDoOutput(true); // 设置允许输出
            httpConnection.setDoInput(true);
            httpConnection.setUseCaches(false); // 设置不用缓存
            httpConnection.setConnectTimeout(6000);
            httpConnection.setReadTimeout(6000);

            httpConnection.connect();
            returnCode = httpConnection.getResponseCode(); // 查看请求是否成功

            if (returnCode == HttpURLConnection.HTTP_OK) {// 请求发送成功
                ObjectInputStream ois = new ObjectInputStream(httpConnection.getInputStream());
                byte[] b = new byte[4096];
                ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
                for (int n; (n = ois.read(b)) != -1; ) {
                    byteOut.write(b, 0, n);
                }
                ois.close();
                String strToken = new String(byteOut.toByteArray(), "UTF-8");
                if (!isEmpty(strToken) && strToken.toLowerCase().contains("true")) {
                    return true;
                }
            }
            httpConnection.disconnect();
        } catch (Exception e){
            e.printStackTrace();
            HttpBasicLogger.error("调用第三方令牌服务异常", e.getMessage());
        }
        return false;
    }

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
