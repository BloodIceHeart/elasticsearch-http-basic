package com.asquera.elasticsearch.plugins.http;

import com.asquera.elasticsearch.plugins.http.auth.Authenticator;
import org.elasticsearch.client.Client;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class HttpBasicServerFilter extends RestFilter {
    Client client;
    Authenticator authenticator;

    public HttpBasicServerFilter(Client client, Authenticator authenticator) {
        this.client = client;
        this.authenticator = authenticator;
    }

    @Override
    public void process(RestRequest request, RestChannel channel, RestFilterChain filterChain) throws Exception {
        try {
            if (Authenticator.isPluginEnabled()) {
                authenticator.dispatchRequest(request, channel, filterChain);
            } else {
                filterChain.continueProcessing(request, channel);
            }
        } catch (Exception exp) {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, "HttpBasicServerFilter internal exception"));
        }
        return;
    }
}
