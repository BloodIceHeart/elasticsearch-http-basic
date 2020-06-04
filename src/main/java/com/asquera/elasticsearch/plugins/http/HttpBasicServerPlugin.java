package com.asquera.elasticsearch.plugins.http;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;

public class HttpBasicServerPlugin extends Plugin {

    private boolean enabledByDefault = true;
    private final Settings settings;

    @Inject
    public HttpBasicServerPlugin(Settings settings) {
        this.settings = settings;
    }

    @Override
    public String name() {
        return "http-basic-server-plugin";
    }

    @Override
    public String description() {
        return "HTTP Basic Server Plugin";
    }

    public void onModule(RestModule module) {
        module.addRestAction(HttpBasicServerHandler.class);
    }
}
