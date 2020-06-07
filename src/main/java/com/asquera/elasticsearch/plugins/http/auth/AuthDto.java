package com.asquera.elasticsearch.plugins.http.auth;

import com.asquera.elasticsearch.plugins.http.HttpBasicLogger;

public class AuthDto {
    //用户
    private String user;
    //密码
    private String password;
    //白名单
    private InetAddressWhitelist whitelist;
    private ProxyChains proxyChains;
    private String xForwardHeader;
    //日志开关
    private boolean log;
    //WEB登录校验开关
    private boolean login;
    //令牌字段名
    private String tokenName;
    //令牌验证服务
    private String tokenUri;
    //令牌超时时间设置
    private Long token_timeout = 1800000L;
    //令牌清理上线
    private int token_size = 20;

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public InetAddressWhitelist getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(InetAddressWhitelist whitelist) {
        this.whitelist = whitelist;
    }

    public ProxyChains getProxyChains() {
        return proxyChains;
    }

    public void setProxyChains(ProxyChains proxyChains) {
        this.proxyChains = proxyChains;
    }

    public String getxForwardHeader() {
        return xForwardHeader;
    }

    public void setxForwardHeader(String xForwardHeader) {
        this.xForwardHeader = xForwardHeader;
    }

    public boolean isLog() {
        return log;
    }

    public void setLog(boolean log) {
        this.log = log;
    }

    public boolean isLogin() {
        return login;
    }

    public void setLogin(boolean login) {
        this.login = login;
    }

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public Long getToken_timeout() {
        return token_timeout;
    }

    public void setToken_timeout(Long token_timeout) {
        this.token_timeout = token_timeout;
    }

    public int getToken_size() {
        return token_size;
    }

    public void setToken_size(int token_size) {
        this.token_size = token_size;
    }

    public void log() {
        HttpBasicLogger.info("using {}:{} with whitelist: {}, xforward header field: {}, trusted proxy chain: {}",
                user, password, whitelist, xForwardHeader, proxyChains);
        HttpBasicLogger.info("using log:{}, login:{}, tokenName:{}, tokenUri:{}, token_timeout:{}, token_size:{}",
                log, login, tokenName, tokenUri, token_timeout, token_size);
    }
}
