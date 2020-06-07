package com.asquera.elasticsearch.plugins.http.auth;

import com.asquera.elasticsearch.plugins.http.HttpBasicLogger;
import com.asquera.elasticsearch.plugins.http.security.TokenUtil;
import org.elasticsearch.common.Base64;
import org.elasticsearch.rest.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.common.Strings.isEmpty;
import static org.elasticsearch.rest.RestStatus.UNAUTHORIZED;

public class Authenticator {
    private static boolean pluginEnabled = true;
    private static final String login_index = "/_plugin/http-basic/index.html";
    private static final String head_index = "/_plugin/head";
    private static final String login_user = "httpbasic_user";
    private static final String login_password = "httpbasic_password";
    private static final ConcurrentHashMap<String, Long> ssoMaps = new ConcurrentHashMap<String, Long>();
    private final AuthDto auth;
    private static final ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1,
            0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<Runnable>(1));

    public Authenticator(AuthDto auth) {
        this.auth = auth;
    }

    /**
     * @param request
     * @param channel
     * @param filterChain
     * @return check the request is authorized
     */
    public void dispatchRequest(final RestRequest request, final RestChannel channel, final RestFilterChain filterChain) {
        if (auth.isLog()) {
            logRequest(request);
        }
        //登录页面
        if (auth.isLogin() && this.login_index.equals(request.path())) {
            //登录成功的需要回写token
            Map<String, String> maps = this.getContent(request);
            if (loginCheck(request)) {
                String strToken = this.getToken(request);
                String indexUrl = "http://" + request.header("Host") + this.head_index;
                String content = "<script languge='javascript'>window.location.href='" + indexUrl +"'</script>";
                BytesRestResponse response = new BytesRestResponse(RestStatus.OK, content);
                response.addHeader("set-Cookie", auth.getTokenName() + "=" + strToken + ";Max-Age=1800;path=/");
                response.addHeader("P3P", "CP=\"NOI ADM DEV COM NAV OUR\"");
                response.addHeader("Content-Type", "text/html");
                channel.sendResponse(response);
            } else if (maps.containsKey(login_user) && maps.containsKey(login_password)) {//登录失败
                String indexUrl = "http://" + request.header("Host") + this.login_index;
                String content = "<script languge='javascript'>alert('用户密码有误，请重新登录！');window.location.href='" + indexUrl +"'</script>";
                BytesRestResponse response = new BytesRestResponse(RestStatus.OK, content);
                response.addHeader("Content-Type", "text/html; charset=UTF-8");
                channel.sendResponse(response);
            } else {
                filterChain.continueProcessing(request, channel);
            }
        } else if (healthCheck(request) || authorized(request)) {
            filterChain.continueProcessing(request, channel);
        } else {
            logUnAuthorizedRequest(request);
            //请求插件页面才返回登录页面，其他只返回错误信息
            if (request.path().startsWith("/_plugin/")) {
                BytesRestResponse response;
                if (auth.isLogin()) {
                    response = new BytesRestResponse(RestStatus.FOUND, "The resource you requested requires authorize");
                    response.addHeader("Location", "http://" + request.header("Host") + this.login_index);
                } else {
                    response = new BytesRestResponse(UNAUTHORIZED, "Authentication Required");
                    response.addHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
                }
                channel.sendResponse(response);
            } else {
                BytesRestResponse res = new BytesRestResponse(RestStatus.FORBIDDEN, "Forbidden Method Request by httpbasic plugin");
                channel.sendResponse(res);
            }
        }
    }

    /**
     * @param request
     * @return boolean if the request is authorized
     */
    private boolean authorized(final RestRequest request) {
        return hasLogin(request) || allowOptionsForCORS(request) || ipAuthorized(request) || authBasic(request);
    }

    /**
     * @param request
     * @return True 登录验证
     */
    private boolean loginCheck(final RestRequest request) {
        boolean loginSuccess = this.login(request);
        boolean hasLogin = this.hasLogin(request);
        return loginSuccess || hasLogin;
    }

    /**
     * @param request
     * @return True 用户密码登录验证
     */
    private boolean login(final RestRequest request) {
        String givenUser = "";
        String givenPass = "";
        try {
            Map<String, String> maps = this.getContent(request);
            if (maps.containsKey(login_user) && maps.containsKey(login_password)) {
                givenUser = maps.get(login_user);
                givenPass = maps.get(login_password);
                if (auth.getUser().equals(givenUser) && auth.getPassword().equals(givenPass)) {
                    if (auth.isLog()) {
                        HttpBasicLogger.info("Login Authorized success of user {} and password {}", maps.get(login_user), maps.get(login_password));
                    }
                    return true;
                } else {
                    HttpBasicLogger.error("Login Authorized failed of user {} and password {}", maps.get(login_user), maps.get(login_password));
                }
            }
        } catch (Exception e) {
            HttpBasicLogger.warn("Retrieving of user {} and password {} login Authorized failed", givenUser, givenPass);
        }
        return false;
    }

    /**
     * @param request
     * @return Map 获取登录请求参数
     */
    private Map<String, String> getContent(RestRequest request) {
        String strContent = request.content().toUtf8();
        String[] strContents = strContent.split("&");
        Map<String, String> maps = new HashMap<String, String>();
        if (strContents.length > 0) {
            for (int i = 0; i < strContents.length; i++) {
                String[] strings = strContents[i].split("=");
                if (strings.length > 1) {
                    maps.put(strings[0], strings[1]);
                }
            }
        }
        return maps;
    }

    /**
     * @param request
     * @return True token登录验证
     */
    private boolean hasLogin(final RestRequest request) {
        String strToken = "";
        try {
            strToken = getTokenFromCookie(request);
            if (!isEmpty(strToken)) {
                //验证令牌有效性1、本地有数据且未超时；2、本地无数据且第三方验证通过。
                if ((ssoMaps.containsKey(strToken) && System.currentTimeMillis() - ssoMaps.get(strToken) < auth.getToken_timeout()) ||
                        (!isEmpty(auth.getTokenUri()) && !ssoMaps.containsKey(strToken) && TokenUtil.tokenService(auth.getTokenUri(), auth.getTokenName(), strToken))) {
                    if (auth.isLog()) {
                        if (ssoMaps.containsKey(strToken)) {
                            HttpBasicLogger.info("Token Authorized success of {} effective time {}", strToken, System.currentTimeMillis() - ssoMaps.get(strToken));
                        } else {
                            HttpBasicLogger.info("Token Authorized success of {} effective time {}", strToken, auth.getToken_timeout());
                        }
                    }
                    return true;
                } else {
                    HttpBasicLogger.error("Token Authorized failed of {} ", strToken);
                }
            }
        } catch (Exception e) {
            HttpBasicLogger.warn("Retrieving of token {} login Authorized failed", strToken);
        }
        return false;
    }

    /**
     * @param request
     * @return String get Token From Cookie
     */
    private String getTokenFromCookie(RestRequest request) {
        if (request.header("Cookie") != null) {
            String strCookie = request.header("Cookie");
            String[] strCookies = strCookie.split(";");
            if (strCookies.length > 0) {
                for (int i = 0; i < strCookies.length; i++) {
                    String[] strings = strCookies[i].split("=");
                    if (strings.length > 1 && auth.getTokenName().equals(strings[0])) {
                        return strings[1];
                    }
                }
            }
        }
        return "";
    }

    /**
     * @param request
     * @return String token Return To user
     */
    private String getToken(RestRequest request) {
        String strToken = this.getTokenFromCookie(request);
        if (isEmpty(strToken) && isEmpty(auth.getTokenUri())) {
            strToken = TokenUtil.genToken(auth.getUser());
        }
        ssoMaps.put(strToken, System.currentTimeMillis());
        if (ssoMaps.size() > auth.getToken_size()) {
            executor.execute(new Thread() {
                @Override
                public void run() {
                    for (String key : Authenticator.getSsoMaps().keySet()) {
                        if (System.currentTimeMillis() - Authenticator.getSsoMaps().get(key) > auth.getToken_timeout()) {
                            Authenticator.getSsoMaps().remove(key);
                        }
                    }
                }
            });
        }
        return strToken;
    }


    /**
     * @param request
     * @return True iff we check the root path and is a method allowed for healthCheck
     */
    private boolean healthCheck(final RestRequest request) {
        return request.path().equals("/") && isHealthCheckMethod(request.method());
    }

    /**
     * @param an http method
     * @return True iff the method is one of the methods used for health check
     */
    private boolean isHealthCheckMethod(final RestRequest.Method method) {
        final RestRequest.Method[] healthCheckMethods = {RestRequest.Method.GET, RestRequest.Method.HEAD};
        return Arrays.asList(healthCheckMethods).contains(method);
    }

    /**
     * https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
     * 规范要求浏览器“预检”请求，进行请求服务器通过HTTP OPTIONS请求支持的方法
     */
    private boolean allowOptionsForCORS(RestRequest request) {
        // in elasticsearch.yml set
        // http.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length, Authorization"
        if (request.method() == RestRequest.Method.OPTIONS) {
            if (auth.isLog()) {
                HttpBasicLogger.info("CORS Authorized success type {}, address {}, path {}, request {}, content {}",
                        request.method(), getAddress(request), request.path(), request.params(), request.content().toUtf8());
            }
            return true;
        }
        return false;
    }

    /**
     * @param request
     * @return true if the client is authorized by ip
     */
    private boolean ipAuthorized(final RestRequest request) {
        boolean ipAuthorized = false;
        String xForwardedFor = request.header(auth.getxForwardHeader());
        Client client = new Client(getAddress(request),
                auth.getWhitelist(),
                new XForwardedFor(xForwardedFor),
                auth.getProxyChains());
        ipAuthorized = client.isAuthorized();
        if (ipAuthorized) {
            if (auth.isLog()) {
                String template = "Ip Authorized success client: {}";
                HttpBasicLogger.info(template, client);
            }
        } else {
            String template = "Ip Unauthorized failed client: {}";
            HttpBasicLogger.error(template, client);
        }
        return ipAuthorized;
    }

    /**
     * 打印请求日志
     * @param request
     */
    private void logRequest(final RestRequest request) {
        String addr = getAddress(request).getHostAddress();
        String t = "Host:{}, type: {}, Path:{}, Cookie:{}, :{}:{}, Request-IP:{}, Client-IP:{}, X-Client-IP{}";
        HttpBasicLogger.info(t,
                request.header("Host"),
                request.method(),
                request.path(),
                this.getTokenFromCookie(request),
                auth.getxForwardHeader(),
                request.header(auth.getxForwardHeader()),
                addr,
                request.header("X-Client-IP"),
                request.header("Client-IP"));
    }

    /**
     * 打印未授权请求日志
     * @param request
     */
    private void logUnAuthorizedRequest(final RestRequest request) {
        String addr = getAddress(request).getHostAddress();
        String t = "UNAUTHORIZED type:{}, address:{}, path:{}, request:{}, Cookie:{}, content:{}, credentials:{}";
        HttpBasicLogger.error(t, request.method(), addr, request.path(), request.params(), this.getTokenFromCookie(request),
                request.content().toUtf8(), getDecoded(request));
    }

    /**
     * @param request
     * @return the IP adress of the direct client
     */
    private InetAddress getAddress(RestRequest request) {
        return ((InetSocketAddress) request.getRemoteAddress()).getAddress();
    }

    /**
     * @param request
     * @return 获取请求参数
     */
    private String getLogInfo(RestRequest request) throws Exception {
        try {
            String pathStr = request.path();
            String ipaddr = ((InetSocketAddress) request.getRemoteAddress()).getAddress().getHostAddress();
            return "The [" + request.method().name() + "] request [" + pathStr + "] is from [" + ipaddr + "]";
        } catch (Exception exp) {
        }
        return "The request resolve failed";
    }

    /**
     * @param request
     * @return 验证用户密码是否正确
     */
    private boolean authBasic(final RestRequest request) {
        String decoded = "";
        try {
            decoded = getDecoded(request);
            if (!decoded.isEmpty()) {
                String[] userAndPassword = decoded.split(":", 2);
                String givenUser = userAndPassword[0];
                String givenPass = userAndPassword[1];
                if (auth.getUser().equals(givenUser) && auth.getPassword().equals(givenPass)) {
                    if (auth.isLog()) {
                        HttpBasicLogger.info("AuthBasic Authorized success of user {} and password {}", givenUser, givenPass);
                    }
                    return true;
                } else {
                    HttpBasicLogger.error("AuthBasic Authorized failed of user {} and password {}", givenUser, givenPass);
                }
            }
        } catch (Exception e) {
            HttpBasicLogger.warn("Retrieving of user and password Authorized failed for " + decoded + " ," + e.getMessage());
        }
        return false;
    }

    /**
     * @param request
     * @return 获取请求头中的用户密码
     */
    private String getDecoded(RestRequest request) {
        String authHeader = request.header("Authorization");
        if (authHeader == null)
            return "";

        String[] split = authHeader.split(" ", 2);
        if (split.length != 2 || !split[0].equals("Basic"))
            return "";
        try {
            return new String(Base64.decode(split[1]));
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static boolean isPluginEnabled() {
        return pluginEnabled;
    }

    public static void setPluginEnabled(boolean pluginEnabled) {
        Authenticator.pluginEnabled = pluginEnabled;
    }

    public static ConcurrentHashMap<String, Long> getSsoMaps() {
        return ssoMaps;
    }
}
