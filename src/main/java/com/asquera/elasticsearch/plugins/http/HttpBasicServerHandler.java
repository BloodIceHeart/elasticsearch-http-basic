package com.asquera.elasticsearch.plugins.http;

import com.asquera.elasticsearch.plugins.http.auth.AuthDto;
import com.asquera.elasticsearch.plugins.http.auth.Authenticator;
import com.asquera.elasticsearch.plugins.http.auth.InetAddressWhitelist;
import com.asquera.elasticsearch.plugins.http.auth.ProxyChains;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HttpBasicServerHandler extends BaseRestHandler {
    @Inject
    public HttpBasicServerHandler(Settings settings, RestController restController, Client client) {
        super(settings, restController, client);
        RestFilter filter = new HttpBasicServerFilter(client, iniAuthenticator(settings));
        restController.registerFilter(filter);
    }

    @Override
    protected void handleRequest(RestRequest restRequest, RestChannel restChannel, Client client)
            throws Exception {
    }

    /**
     * @param settings
     * @return Authenticator 初始化认证器
     */
    public Authenticator iniAuthenticator(final Settings settings) {
        final boolean whitelistEnabled = settings.getAsBoolean("http.basic.ipwhitelist", true);
        String[] whitelisted = new String[]{};
        if (whitelistEnabled) {
            whitelisted = settings.getAsArray("http.basic.ipwhitelist", new String[]{});
        }
        String[] hosts = settings.getAsArray("discovery.zen.ping.unicast.hosts", new String[]{});
        List<String> lists = new ArrayList<String>();
        lists.addAll(Arrays.asList(whitelisted));
        if (!lists.contains("localhost")) {
            lists.add("localhost");
        }
        if (!lists.contains("127.0.0.1")) {
            lists.add("127.0.0.1");
        }
        for (int i = 0; i < hosts.length; i++) {
            String host = hosts[i];
            if (host.indexOf(":") > 0) {
                host = host.substring(0, host.indexOf(":"));
            }
            lists.add(host);
        }
        InetAddressWhitelist whitelist = new InetAddressWhitelist(lists.toArray(new String[lists.size()]));
        ProxyChains proxyChains = new ProxyChains(settings.getAsArray("http.basic.trusted_proxy_chains", new String[]{""}));
        Authenticator.setPluginEnabled(settings.getAsBoolean("http.basic.enabled", true));
        AuthDto auth = new AuthDto();
        auth.setUser(settings.get("http.basic.user", "admin"));
        auth.setPassword(settings.get("http.basic.password", "admin123"));
        auth.setWhitelist(whitelist);
        auth.setProxyChains(proxyChains);
        auth.setxForwardHeader(settings.get("http.basic.xforward", ""));
        auth.setLog(settings.getAsBoolean("http.basic.log", true));
        auth.setLogin(settings.getAsBoolean("http.basic.login", true));
        auth.setTokenName(settings.get("http.basic.token.name", "sinosoftSSO"));
        auth.setTokenUri(settings.get("http.basic.token.uri", ""));
        auth.setToken_timeout(settings.getAsLong("http.basic.token.imeout", 1800000L));
        auth.setToken_size(settings.getAsInt("http.basic.token.size", 20));
        auth.log();
        return new Authenticator(auth);
    }
}
