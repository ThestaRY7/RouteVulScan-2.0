package func;

import UI.Tags;
import burp.Bfunc;
import burp.BurpExtender;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import yaml.YamlUtil;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class vulscan {

    private final HttpRequestResponse source;
    private final HttpRequest seedRequest;
    public String Path_record;
    public BurpExtender burp;
    private final int scanGeneration;
    private final boolean forceCarryHeaders;

    public vulscan(BurpExtender burp, HttpRequestResponse source, HttpRequest requestOverride, String triggerSource, boolean forceCarryHeaders) {
        this.burp = burp;
        this.source = source;
        this.seedRequest = requestOverride != null ? requestOverride : source.request();
        this.scanGeneration = burp.getScanGeneration();
        this.forceCarryHeaders = forceCarryHeaders;
        this.burp.beginScanSession();
        try {
            HttpRequest normalizedRequest = normalizeRequestForPathDiscovery(seedRequest);
            List<HttpHeader> carryHeaders = new ArrayList<HttpHeader>(seedRequest.headers());
            String[] paths = normalizedRequest.pathWithoutQuery().split("/");
            if (paths.length == 0) {
                paths = new String[]{""};
            }

            Map<String, Object> yamlMap = YamlUtil.readYaml(burp.Config_l.yaml_path);
            List<Map<String, Object>> rules = (List<Map<String, Object>>) yamlMap.get("Load_List");
            List<String> bypassList = (List<String>) yamlMap.get("Bypass_List");
            if (bypassList == null) {
                bypassList = new ArrayList<String>();
            }

            String host = source.httpService().host();
            String[] domainNames = AnalysisHost(host);
            if (burp.DomainScan) {
                LaunchPath(true, domainNames, rules, source, carryHeaders, bypassList);
            }
            if (!isCancelled()) {
                LaunchPath(false, paths, rules, source, carryHeaders, bypassList);
            }
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

    private void LaunchPath(Boolean clearPathRecord, String[] paths, List<Map<String, Object>> rules, HttpRequestResponse requestResponse, List<HttpHeader> carryHeaders, List<String> bypassList) {
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
            if (clearPathRecord) {
                this.Path_record = "";
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
                    tasks.add(java.util.concurrent.Executors.callable(new threads(rule, this, requestResponse, carryHeaders, bypassList)));
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
        return forceCarryHeaders || burp.Carry_head;
    }

    public boolean shouldUseSeedRequestTemplate() {
        return forceCarryHeaders;
    }

    public static HashMap<String, String> AnalysisHeaders(List<HttpHeader> headers) {
        HashMap<String, String> headMap = new HashMap<String, String>();
        for (HttpHeader header : headers) {
            headMap.put(header.name(), header.value());
        }
        return headMap;
    }

    public static String[] AnalysisHost(String host) {
        ArrayList<String> exceptSubdomain = new ArrayList<String>(Collections.singletonList("www"));
        Pattern regex = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        Matcher matcher = regex.matcher(host);
        if (!matcher.find()) {
            List<String> hostArray = new ArrayList<String>(Arrays.asList(host.split("\\.")));
            if (!hostArray.isEmpty() && exceptSubdomain.contains(hostArray.get(0))) {
                hostArray.remove(0);
            }
            if (hostArray.size() >= 3 && hostArray.get(hostArray.size() - 1).equals("cn") && hostArray.get(hostArray.size() - 2).equals("com")) {
                hostArray.remove(hostArray.size() - 1);
                hostArray.remove(hostArray.size() - 1);
            } else if (!hostArray.isEmpty()) {
                hostArray.remove(hostArray.size() - 1);
            }
            return hostArray.toArray(new String[0]);
        }
        return new String[]{};
    }
}
