package func;

import UI.Tags;
import burp.BurpExtender;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import yaml.YamlUtil;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class vulscan {

    private final HttpRequestResponse source;
    private final HttpRequest seedRequest;
    private final boolean forceCarryHeaders;
    public String Path_record;
    public BurpExtender burp;
    private final int scanGeneration;

    public vulscan(BurpExtender burp, HttpRequestResponse source, HttpRequest requestOverride, String triggerSource) {
        this(burp, source, requestOverride, triggerSource, false);
    }

    public vulscan(BurpExtender burp, HttpRequestResponse source, HttpRequest requestOverride, String triggerSource, boolean forceCarryHeaders) {
        this.burp = burp;
        this.source = source;
        this.seedRequest = requestOverride != null ? requestOverride : source.request();
        this.forceCarryHeaders = forceCarryHeaders;
        this.scanGeneration = burp.getScanGeneration();
        this.burp.beginScanSession();
        try {
            HttpRequest normalizedRequest = normalizeRequestForPathDiscovery(seedRequest);
            String[] paths = normalizedRequest.pathWithoutQuery().split("/");
            if (paths.length == 0) {
                paths = new String[]{""};
            }

            Map<String, Object> yamlMap = YamlUtil.readYaml(burp.Config_l.yaml_path);
            List<Map<String, Object>> rules = (List<Map<String, Object>>) yamlMap.get("Load_List");

            LaunchPath(paths, rules, source);
        } catch (Throwable t) {
            burp.logError(burp.t("log.scanFailed", triggerSource), t);
        } finally {
            burp.endScanSession();
        }
    }

    private HttpRequest normalizeRequestForPathDiscovery(HttpRequest request) {
        HttpRequest normalized = request;
        if ("POST".equalsIgnoreCase(normalized.method())) {
            normalized = normalized.withMethod("GET");
        }
        List<ParsedHttpParameter> parameters = normalized.parameters();
        if (!parameters.isEmpty()) {
            normalized = normalized.withRemovedParameters(parameters);
        }
        return normalized;
    }

    private void LaunchPath(String[] paths, List<Map<String, Object>> rules, HttpRequestResponse requestResponse) {
        this.Path_record = "";
        URL requestUrl;
        try {
            requestUrl = new URL(requestResponse.request().url());
        } catch (Exception e) {
            burp.logError(burp.t("log.parseUrlFailed"), e);
            return;
        }
        String baseUrl = requestUrl.getProtocol() + "://" + requestUrl.getHost() + ":" + requestUrl.getPort();
        for (String path : paths) {
            if (isCancelled()) {
                return;
            }
            if (path.contains(".") && path.equals(paths[paths.length - 1])) {
                break;
            }
            if (!path.equals("")) {
                this.Path_record = this.Path_record + "/" + path;
            }

            String url = baseUrl + this.Path_record;
            if (this.burp.history_url.add(url)) {
                this.burp.notePathQueued();
                List<Callable<Object>> tasks = new ArrayList<Callable<Object>>();
                for (Map<String, Object> rule : rules) {
                    tasks.add(java.util.concurrent.Executors.callable(new threads(rule, this, requestResponse)));
                }
                try {
                    List<Future<Object>> futures = this.burp.ensureThreadPool().invokeAll(tasks, 31, TimeUnit.SECONDS);
                    for (Future<Object> future : futures) {
                        if (future.isCancelled()) {
                            this.burp.logError(this.burp.t("log.scanTimeout", url));
                            this.burp.noteTimeout();
                            break;
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    this.burp.logError(this.burp.t("log.scanInterrupted", url));
                    this.burp.noteTimeout();
                    return;
                } finally {
                    if (!isCancelled()) {
                        this.burp.notePathCompleted();
                    }
                }
            } else {
                this.burp.logError(this.burp.t("log.skipDuplicate", url));
                this.burp.notePathSkipped();
            }
        }
    }

    public static void ir_add(Tags tags, String name, String method, String url, String state, String info, String length, HttpRequestResponse messageInfo) {
        synchronized (tags) {
            tags.addLogEntry(name, method, url, state, info, length, messageInfo);
        }
    }

    public boolean isCancelled() {
        return this.scanGeneration != this.burp.getScanGeneration();
    }

    public HttpRequestResponse source() {
        return source;
    }

    public HttpRequest seedRequest() {
        return seedRequest;
    }

    public boolean shouldCarryHeaders() {
        return this.forceCarryHeaders || this.burp.Carry_head;
    }

    public static HashMap<String, String> AnalysisHeaders(List<HttpHeader> headers) {
        HashMap<String, String> headMap = new HashMap<String, String>();
        for (HttpHeader header : headers) {
            headMap.put(header.name(), header.value());
        }
        return headMap;
    }
}
