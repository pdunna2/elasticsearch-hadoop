/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.hadoop.rest.commonshttp;


import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.elasticsearch.hadoop.EsHadoopIllegalStateException;
import org.elasticsearch.hadoop.cfg.ConfigurationOptions;
import org.elasticsearch.hadoop.cfg.Settings;
import org.elasticsearch.hadoop.rest.*;
import org.elasticsearch.hadoop.rest.stats.Stats;
import org.elasticsearch.hadoop.rest.stats.StatsAware;
import org.elasticsearch.hadoop.util.ByteSequence;
import org.elasticsearch.hadoop.util.ReflectionUtils;
import org.elasticsearch.hadoop.util.StringUtils;
import org.elasticsearch.hadoop.util.encoding.HttpEncodingTools;


import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSCredentials;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.Socket;
import java.util.*;

/**
 * Transport implemented on top of Commons Http. Provides transport retries.
 */
public class CommonsHttpTransport implements Transport, StatsAware {

    private static Log log = LogFactory.getLog(CommonsHttpTransport.class);
    private static final Method GET_SOCKET;

    static {
        GET_SOCKET = ReflectionUtils.findMethod(HttpConnection.class, "getSocket", (Class[]) null);
        ReflectionUtils.makeAccessible(GET_SOCKET);
    }


    private final HttpClient client;
    private final HeaderProcessor headers;
    protected Stats stats = new Stats();
    private HttpConnection conn;
    private String proxyInfo = "";
    private final String httpInfo;
    private final boolean sslEnabled;
    private final String pathPrefix;
    private final Settings settings;

    private static class ResponseInputStream extends DelegatingInputStream implements ReusableInputStream {

        private final HttpMethod method;
        private final boolean reusable;

        public ResponseInputStream(HttpMethod http) throws IOException {
            super(http.getResponseBodyAsStream());
            this.method = http;
            reusable = (delegate() instanceof ByteArrayInputStream);
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return super.equals(obj);
        }

        @Override
        public InputStream copy() {
            try {
                return (reusable ? method.getResponseBodyAsStream() : null);
            } catch (IOException ex) {
                throw new EsHadoopIllegalStateException(ex);
            }
        }

        @Override
        public void close() throws IOException {
            if (!isNull()) {
                try {
                    super.close();
                } catch (IOException e) {
                    // silently ignore
                }
            }
            method.releaseConnection();
        }
    }

    private class SocketTrackingConnectionManager extends SimpleHttpConnectionManager {

        @Override
        public HttpConnection getConnectionWithTimeout(HostConfiguration hostConfiguration, long timeout) {
            conn = super.getConnectionWithTimeout(hostConfiguration, timeout);
            return conn;
        }

        public void close() {
            if (httpConnection != null) {
                if (httpConnection.isOpen()) {
                    releaseConnection(httpConnection);
                }

                httpConnection.close();
            }

            httpConnection = null;
            conn = null;
        }
    }

    public CommonsHttpTransport(Settings settings, String host) {
        this.settings = settings;
        httpInfo = host;
        sslEnabled = settings.getNetworkSSLEnabled();

        String pathPref = settings.getNodesPathPrefix();
        pathPrefix = (StringUtils.hasText(pathPref) ? addLeadingSlashIfNeeded(StringUtils.trimWhitespace(pathPref)) : StringUtils.trimWhitespace(pathPref));

        HttpClientParams params = new HttpClientParams();
        params.setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(
                settings.getHttpRetries(), false) {

            @Override
            public boolean retryMethod(HttpMethod method, IOException exception, int executionCount) {
                if (super.retryMethod(method, exception, executionCount)) {
                    stats.netRetries++;
                    return true;
                }
                return false;
            }
        });

        // Max time to wait for a connection from the connectionMgr pool
        params.setConnectionManagerTimeout(settings.getHttpTimeout());
        // Max time to wait for data from a connection.
        params.setSoTimeout((int) settings.getHttpTimeout());
        // explicitly set the charset
        params.setCredentialCharset(StringUtils.UTF_8.name());
        params.setContentCharset(StringUtils.UTF_8.name());

        HostConfiguration hostConfig = new HostConfiguration();

        hostConfig = setupSSLIfNeeded(settings, hostConfig);
        hostConfig = setupSocksProxy(settings, hostConfig);
        Object[] authSettings = setupHttpOrHttpsProxy(settings, hostConfig);
        hostConfig = (HostConfiguration) authSettings[0];

        try {
            hostConfig.setHost(new URI(escapeUri(host, sslEnabled), false));
        } catch (IOException ex) {
            throw new EsHadoopTransportException("Invalid target URI " + host, ex);
        }
        client = new HttpClient(params, new SocketTrackingConnectionManager());
        client.setHostConfiguration(hostConfig);

        addHttpAuth(settings, authSettings);
        completeAuth(authSettings);

        HttpConnectionManagerParams connectionParams = client.getHttpConnectionManager().getParams();
        // make sure to disable Nagle's protocol
        connectionParams.setTcpNoDelay(true);
        // Max time to wait to establish an initial HTTP connection
        connectionParams.setConnectionTimeout((int) settings.getHttpTimeout());

        this.headers = new HeaderProcessor(settings);

        if (log.isTraceEnabled()) {
            log.trace("Opening HTTP transport to " + httpInfo);
        }
    }

    private HostConfiguration setupSSLIfNeeded(Settings settings, HostConfiguration hostConfig) {
        if (!sslEnabled) {
            return hostConfig;
        }

        // we actually have a socks proxy, let's start the setup
        if (log.isDebugEnabled()) {
            log.debug("SSL Connection enabled");
        }

        //
        // switch protocol
        // due to how HttpCommons work internally this dance is best to be kept as is
        //
        String schema = "https";
        int port = 443;
        SecureProtocolSocketFactory sslFactory = new SSLSocketFactory(settings);

        replaceProtocol(sslFactory, schema, port);

        return hostConfig;
    }

    private void addHttpAuth(Settings settings, Object[] authSettings) {
        if (StringUtils.hasText(settings.getNetworkHttpAuthUser())) {
            HttpState state = (authSettings[1] != null ? (HttpState) authSettings[1] : new HttpState());
            authSettings[1] = state;
            state.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(settings.getNetworkHttpAuthUser(), settings.getNetworkHttpAuthPass()));
            if (log.isDebugEnabled()) {
                log.info("Using detected HTTP Auth credentials...");
            }
        }
    }

    private void completeAuth(Object[] authSettings) {
        if (authSettings[1] != null) {
            client.setState((HttpState) authSettings[1]);
            client.getParams().setAuthenticationPreemptive(true);
        }
    }

    private Object[] setupHttpOrHttpsProxy(Settings settings, HostConfiguration hostConfig) {
        // return HostConfiguration + HttpState
        Object[] results = new Object[2];
        results[0] = hostConfig;
        // set proxy settings
        String proxyHost = null;
        int proxyPort = -1;

        if (sslEnabled) {
            if (settings.getNetworkHttpsUseSystemProperties()) {
                proxyHost = System.getProperty("https.proxyHost");
                proxyPort = Integer.getInteger("https.proxyPort", -1);
            }
            if (StringUtils.hasText(settings.getNetworkProxyHttpsHost())) {
                proxyHost = settings.getNetworkProxyHttpsHost();
            }
            if (settings.getNetworkProxyHttpsPort() > 0) {
                proxyPort = settings.getNetworkProxyHttpsPort();
            }
        }
        else {
            if (settings.getNetworkHttpUseSystemProperties()) {
                proxyHost = System.getProperty("http.proxyHost");
                proxyPort = Integer.getInteger("http.proxyPort", -1);
            }
            if (StringUtils.hasText(settings.getNetworkProxyHttpHost())) {
                proxyHost = settings.getNetworkProxyHttpHost();
            }
            if (settings.getNetworkProxyHttpPort() > 0) {
                proxyPort = settings.getNetworkProxyHttpPort();
            }
        }

        if (StringUtils.hasText(proxyHost)) {
            hostConfig.setProxy(proxyHost, proxyPort);
            proxyInfo = proxyInfo.concat(String.format(Locale.ROOT, "[%s proxy %s:%s]", (sslEnabled ? "HTTPS" : "HTTP"), proxyHost, proxyPort));

            // client is not yet initialized so postpone state
            if (sslEnabled) {
                if (StringUtils.hasText(settings.getNetworkProxyHttpsUser())) {
                    if (!StringUtils.hasText(settings.getNetworkProxyHttpsPass())) {
                        log.warn(String.format("HTTPS proxy user specified but no/empty password defined - double check the [%s] property", ConfigurationOptions.ES_NET_PROXY_HTTPS_PASS));
                    }
                    HttpState state = new HttpState();
                    state.setProxyCredentials(AuthScope.ANY, new UsernamePasswordCredentials(settings.getNetworkProxyHttpsUser(), settings.getNetworkProxyHttpsPass()));
                    // client is not yet initialized so simply save the object for later
                    results[1] = state;
                }

                if (log.isDebugEnabled()) {
                    if (StringUtils.hasText(settings.getNetworkProxyHttpsUser())) {
                        log.debug(String.format("Using authenticated HTTPS proxy [%s:%s]", proxyHost, proxyPort));
                    }
                    else {
                        log.debug(String.format("Using HTTPS proxy [%s:%s]", proxyHost, proxyPort));
                    }
                }
            }
            else {
                if (StringUtils.hasText(settings.getNetworkProxyHttpUser())) {
                    if (!StringUtils.hasText(settings.getNetworkProxyHttpPass())) {
                        log.warn(String.format("HTTP proxy user specified but no/empty password defined - double check the [%s] property", ConfigurationOptions.ES_NET_PROXY_HTTP_PASS));
                    }
                    HttpState state = new HttpState();
                    state.setProxyCredentials(AuthScope.ANY, new UsernamePasswordCredentials(settings.getNetworkProxyHttpUser(), settings.getNetworkProxyHttpPass()));
                    // client is not yet initialized so simply save the object for later
                    results[1] = state;
                }

                if (log.isDebugEnabled()) {
                    if (StringUtils.hasText(settings.getNetworkProxyHttpUser())) {
                        log.debug(String.format("Using authenticated HTTP proxy [%s:%s]", proxyHost, proxyPort));
                    }
                    else {
                        log.debug(String.format("Using HTTP proxy [%s:%s]", proxyHost, proxyPort));
                    }
                }
            }
        }

        return results;
    }

    private HostConfiguration setupSocksProxy(Settings settings, HostConfiguration hostConfig) {
        // set proxy settings
        String proxyHost = null;
        int proxyPort = -1;
        String proxyUser = null;
        String proxyPass = null;

        if (settings.getNetworkHttpUseSystemProperties()) {
            proxyHost = System.getProperty("socksProxyHost");
            proxyPort = Integer.getInteger("socksProxyPort", -1);
            proxyUser = System.getProperty("java.net.socks.username");
            proxyPass = System.getProperty("java.net.socks.password");
        }
        if (StringUtils.hasText(settings.getNetworkProxySocksHost())) {
            proxyHost = settings.getNetworkProxySocksHost();
        }
        if (settings.getNetworkProxySocksPort() > 0) {
            proxyPort = settings.getNetworkProxySocksPort();
        }
        if (StringUtils.hasText(settings.getNetworkProxySocksUser())) {
            proxyUser = settings.getNetworkProxySocksUser();
        }
        if (StringUtils.hasText(settings.getNetworkProxySocksPass())) {
            proxyPass = settings.getNetworkProxySocksPass();
        }

        // we actually have a socks proxy, let's start the setup
        if (StringUtils.hasText(proxyHost)) {
            proxyInfo = proxyInfo.concat(String.format("[SOCKS proxy %s:%s]", proxyHost, proxyPort));

            if (!StringUtils.hasText(proxyUser)) {
                log.warn(String.format(
                        "SOCKS proxy user specified but no/empty password defined - double check the [%s] property",
                        ConfigurationOptions.ES_NET_PROXY_SOCKS_PASS));
            }

            if (log.isDebugEnabled()) {
                if (StringUtils.hasText(proxyUser)) {
                    log.debug(String.format("Using authenticated SOCKS proxy [%s:%s]", proxyHost, proxyPort));
                }
                else {
                    log.debug(String.format("Using SOCKS proxy [%s:%s]", proxyHost, proxyPort));
                }
            }

            //
            // switch protocol
            // due to how HttpCommons work internally this dance is best to be kept as is
            //
            String schema = sslEnabled ? "https" : "http";
            int port = sslEnabled ? 443 : 80;
            SocksSocketFactory socketFactory = new SocksSocketFactory(proxyHost, proxyPort, proxyUser, proxyPass);
            replaceProtocol(socketFactory, schema, port);
        }

        return hostConfig;
    }

    static void replaceProtocol(ProtocolSocketFactory socketFactory, String schema, int defaultPort) {
        //
        // switch protocol
        // due to how HttpCommons work internally this dance is best to be kept as is
        //

        Protocol directHttp = Protocol.getProtocol(schema);
        if (directHttp instanceof DelegatedProtocol) {
            // unwrap the original
            directHttp = ((DelegatedProtocol)directHttp).getOriginal();
            assert directHttp instanceof DelegatedProtocol == false;
        }
        Protocol proxiedHttp = new DelegatedProtocol(socketFactory, directHttp, schema, defaultPort);
        // NB: register the new protocol since when using absolute URIs, HttpClient#executeMethod will override the configuration (#387)
        // NB: hence why the original/direct http protocol is saved - as otherwise the connection is not closed since it is considered different
        // NB: (as the protocol identities don't match)

        // this is not really needed since it's being replaced later on
        // hostConfig.setHost(proxyHost, proxyPort, proxiedHttp);
        Protocol.registerProtocol(schema, proxiedHttp);

        // end dance
    }

    @Override
    public Response execute(Request request) throws IOException {
        HttpMethod http = null;
        HttpMethodName awsHttpMethod = HttpMethodName.GET;

        switch (request.method()) {
            case DELETE:
                http = new DeleteMethodWithBody();
                awsHttpMethod = HttpMethodName.DELETE;
                break;
            case HEAD:
                http = new HeadMethod();
                awsHttpMethod = HttpMethodName.HEAD;
                break;
            case GET:
                http = (request.body() == null ? new GetMethod() : new GetMethodWithBody());
                awsHttpMethod = HttpMethodName.GET;
                break;
            case POST:
                http = new PostMethod();
                awsHttpMethod = HttpMethodName.POST;
                break;
            case PUT:
                http = new PutMethod();
                awsHttpMethod = HttpMethodName.PUT;
                break;

            default:
                throw new EsHadoopTransportException("Unknown request method " + request.method());
        }

        CharSequence uri = request.uri();
        if (StringUtils.hasText(uri)) {
            if (String.valueOf(uri).contains("?")) {
                throw new EsHadoopInvalidRequest("URI has query portion on it: [" + uri + "]");
            }
            http.setURI(new URI(escapeUri(uri.toString(), sslEnabled), false));
        }

        // NB: initialize the path _after_ the URI otherwise the path gets reset to /
        // add node prefix (if specified)
        String path = pathPrefix + addLeadingSlashIfNeeded(request.path().toString());
        if (path.contains("?")) {
            throw new EsHadoopInvalidRequest("Path has query portion on it: [" + path + "]");
        }

        path = HttpEncodingTools.encodePath(path);

        http.setPath(path);

        try {
            // validate new URI
            uri = http.getURI().toString();
        } catch (URIException uriex) {
            throw new EsHadoopTransportException("Invalid target URI " + request, uriex);
        }

        DefaultRequest<Void>  defaultRequest = new DefaultRequest<Void>("es");

        CharSequence params = request.params();
        if (StringUtils.hasText(params)) {
            http.setQueryString(params.toString());

            Map<String, List<String>> paramsMap = new LinkedHashMap<String, List<String>>();
            List<String> paramsList = StringUtils.tokenize(params.toString(), "&");

            for (String paramSet : paramsList){
                List<String> pair = StringUtils.tokenize(paramSet, "=");
                List<String> vals = StringUtils.tokenize(pair.get(1));
                paramsMap.put(pair.get(0), vals);
            }
            defaultRequest.setParameters(paramsMap);
        }

        ByteSequence ba = request.body();
        if (ba != null && ba.length() > 0) {
            if (!(http instanceof EntityEnclosingMethod)) {
                throw new IllegalStateException(String.format("Method %s cannot contain body - implementation bug", request.method().name()));
            }
            EntityEnclosingMethod entityMethod = (EntityEnclosingMethod) http;
            entityMethod.setRequestEntity(new BytesArrayRequestEntity(ba));
            entityMethod.setContentChunked(false);

            ByteArrayOutputStream ops = new ByteArrayOutputStream();
            ba.writeTo(ops);
            ByteArrayInputStream ips = new ByteArrayInputStream(ops.toByteArray());
            defaultRequest.setContent(ips);
        }

        defaultRequest.setHttpMethod(awsHttpMethod);
        defaultRequest.setEndpoint(java.net.URI.create(httpInfo));
        defaultRequest.setResourcePath(path);

        //System.out.println("*************************** Host URL : " + httpInfo+uri.toString());

        AWS4Signer signer = new AWS4Signer();
        signer.setRegionName("us-west-2");
        signer.setServiceName("es");
        AWSCredentials creds = DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
        //System.out.println("*************************** Default request before signing : " +  defaultRequest.toString());

        signer.sign(defaultRequest, creds);

        //System.out.println("*************************** request  : " +  request.toString());
        //System.out.println("*************************** Default request  : " +  defaultRequest.toString());
        //System.out.println("*************************** Authorization header  : " +  defaultRequest.getHeaders().get("Authorization"));
        //System.out.println("*************************** X-Amz-Date  : " +  defaultRequest.getHeaders().get("X-Amz-Date"));

        headers.AddHeader("Authorization", defaultRequest.getHeaders().get("Authorization"));
        headers.AddHeader("X-Amz-Date", defaultRequest.getHeaders().get("X-Amz-Date"));
        headers.AddHeader("X-Amz-Security-Token", defaultRequest.getHeaders().get("X-Amz-Security-Token"));

        headers.applyTo(http);


        // when tracing, log everything
        if (log.isTraceEnabled()) {
            log.trace(String.format("Tx %s[%s]@[%s][%s]?[%s] w/ payload [%s]", proxyInfo, request.method().name(), httpInfo, request.path(), request.params(), request.body()));
        }

        long start = System.currentTimeMillis();
        try {
            client.executeMethod(http);
        } finally {
            stats.netTotalTime += (System.currentTimeMillis() - start);
        }

        if (log.isTraceEnabled()) {
            Socket sk = ReflectionUtils.invoke(GET_SOCKET, conn, (Object[]) null);
            String addr = sk.getLocalAddress().getHostAddress();
            log.trace(String.format("Rx %s@[%s] [%s-%s] [%s]", proxyInfo, addr, http.getStatusCode(), HttpStatus.getStatusText(http.getStatusCode()), http.getResponseBodyAsString()));
        }

        // the request URI is not set (since it is retried across hosts), so use the http info instead for source
        return new SimpleResponse(http.getStatusCode(), new ResponseInputStream(http), httpInfo);
    }

    @Override
    public void close() {
        if (log.isTraceEnabled()) {
            log.trace("Closing HTTP transport to " + httpInfo);
        }

        HttpConnectionManager manager = client.getHttpConnectionManager();
        if (manager instanceof SocketTrackingConnectionManager) {
            try {
                ((SocketTrackingConnectionManager) manager).close();
            } catch (NullPointerException npe) {
                // ignore
            } catch (Exception ex) {
                // log - not much else to do
                log.warn("Exception closing underlying HTTP manager", ex);
            }
        }
    }

    private static String escapeUri(String uri, boolean ssl) {
        // escape the uri right away
        String escaped = HttpEncodingTools.encodeUri(uri);
        return escaped.contains("://") ? escaped : (ssl ? "https://" : "http://") + escaped;
    }

    private static String addLeadingSlashIfNeeded(String string) {
        return string.startsWith("/") ? string : "/" + string;
    }

    @Override
    public Stats stats() {
        return stats;
    }
}