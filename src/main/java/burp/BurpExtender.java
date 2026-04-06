package burp;

import UI.Tags;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import func.vulscan;
import utils.DomainNameRepeat;
import utils.UrlRepeat;
import yaml.YamlUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    public static String Yaml_Path = System.getProperty("user.dir") + "/" + "Config_yaml.yaml";
    public static String EXPAND_NAME = "Route Vulnerable Scan";
    public static String VERSION = "2.0.0";
    public static String Download_Yaml_protocol = "https";
    public static String Download_Yaml_host = "raw.githubusercontent.com";
    public static int Download_Yaml_port = 443;
    public static String Download_Yaml_file = "/F6JO/RouteVulScan/main/Config_yaml.yaml";

    private static Logging staticLogging;

    public MontoyaApi api;
    public Logging logging;
    public Tags tags;
    public Config Config_l;
    public ExecutorService ThreadPool;
    public boolean Carry_head = false;
    public boolean on_off = false;
    public boolean Bypass = false;
    public boolean DomainScan = false;
    public final Set<String> history_url = Collections.synchronizedSet(new LinkedHashSet<String>());
    public Map<String, View> views;
    public JTextField Host_txtfield;
    private final UrlRepeat urlC = new UrlRepeat();
    private final DomainNameRepeat domainNameRepeat = new DomainNameRepeat();
    private final AtomicInteger scanGeneration = new AtomicInteger(0);
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private final AtomicInteger pathsQueued = new AtomicInteger(0);
    private final AtomicInteger pathsCompleted = new AtomicInteger(0);
    private final AtomicInteger runningTasks = new AtomicInteger(0);
    private final AtomicInteger finishedTasks = new AtomicInteger(0);
    private final AtomicInteger matchesFound = new AtomicInteger(0);
    private final AtomicInteger timeoutCount = new AtomicInteger(0);
    private final AtomicInteger skippedPaths = new AtomicInteger(0);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        staticLogging = this.logging;
        api.extension().setName(EXPAND_NAME + " " + VERSION);
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                if (ThreadPool != null && !ThreadPool.isShutdown()) {
                    ThreadPool.shutdownNow();
                }
            }
        });

        try {
            YamlUtil.writeYaml(YamlUtil.readYaml(Yaml_Path), Yaml_Path);
            this.Config_l = new Config(this);
            this.tags = new Tags(this, Config_l);
            this.ThreadPool = Executors.newFixedThreadPool(getConfiguredThreadCount());
            Component suiteTab = tags.getUiComponent();
            if (suiteTab == null) {
                throw new IllegalStateException("RouteVulScan UI root component was not created");
            }
            api.userInterface().registerSuiteTab("RouteVulScan", suiteTab);
            logInfo("@Info: RouteVulScan UI tab registered");
            api.userInterface().registerContextMenuItemsProvider(this);
            api.http().registerHttpHandler(this);
            logInfo("@Info: Loading RouteVulScan success");
            logInfo("@Version: RouteVulScan " + VERSION);
            logInfo("@From: Code by 风沙吹奏");
        } catch (Throwable t) {
            logError("插件初始化失败", t);
        }
    }

    public synchronized int getConfiguredThreadCount() {
        if (Config_l == null || Config_l.spinner1 == null) {
            return 10;
        }
        return (Integer) Config_l.spinner1.getValue();
    }

    public synchronized ExecutorService ensureThreadPool() {
        if (this.ThreadPool == null || this.ThreadPool.isShutdown() || this.ThreadPool.isTerminated()) {
            this.ThreadPool = Executors.newFixedThreadPool(getConfiguredThreadCount());
        }
        return this.ThreadPool;
    }

    public synchronized void resetThreadPool() {
        if (this.ThreadPool != null && !this.ThreadPool.isShutdown()) {
            this.ThreadPool.shutdownNow();
        }
        this.ThreadPool = Executors.newFixedThreadPool(getConfiguredThreadCount());
    }

    public void beginScanSession() {
        activeScans.incrementAndGet();
        notifyProgressChanged();
    }

    public void endScanSession() {
        if (activeScans.get() > 0) {
            activeScans.decrementAndGet();
        }
        notifyProgressChanged();
    }

    public void notePathQueued() {
        pathsQueued.incrementAndGet();
        notifyProgressChanged();
    }

    public void notePathCompleted() {
        pathsCompleted.incrementAndGet();
        notifyProgressChanged();
    }

    public void noteTaskStarted() {
        runningTasks.incrementAndGet();
        notifyProgressChanged();
    }

    public void noteTaskFinished() {
        if (runningTasks.get() > 0) {
            runningTasks.decrementAndGet();
        }
        finishedTasks.incrementAndGet();
        notifyProgressChanged();
    }

    public void noteMatchFound() {
        matchesFound.incrementAndGet();
        notifyProgressChanged();
    }

    public void noteTimeout() {
        timeoutCount.incrementAndGet();
        notifyProgressChanged();
    }

    public void notePathSkipped() {
        skippedPaths.incrementAndGet();
        notifyProgressChanged();
    }

    public void cancelActiveScans() {
        scanGeneration.incrementAndGet();
        resetThreadPool();
        notifyProgressChanged();
    }

    public int getScanGeneration() {
        return scanGeneration.get();
    }

    public int getActiveScanCount() {
        return activeScans.get();
    }

    public int getPathsQueuedCount() {
        return pathsQueued.get();
    }

    public int getPathsCompletedCount() {
        return pathsCompleted.get();
    }

    public int getRunningTaskCount() {
        return runningTasks.get();
    }

    public int getFinishedTaskCount() {
        return finishedTasks.get();
    }

    public int getMatchCount() {
        return matchesFound.get();
    }

    public int getTimeoutCount() {
        return timeoutCount.get();
    }

    public int getSkippedPathCount() {
        return skippedPaths.get();
    }

    public void resetScanMetrics() {
        pathsQueued.set(0);
        pathsCompleted.set(0);
        runningTasks.set(0);
        finishedTasks.set(0);
        matchesFound.set(0);
        timeoutCount.set(0);
        skippedPaths.set(0);
        activeScans.set(0);
        notifyProgressChanged();
    }

    public void notifyProgressChanged() {
        if (Config_l != null) {
            Config_l.refreshProgressView();
        }
    }

    public static void logStaticError(String message) {
        if (staticLogging != null) {
            staticLogging.logToError(message);
        }
    }

    public static void logStaticError(String scene, Throwable t) {
        if (staticLogging != null) {
            staticLogging.logToError(formatThrowable(scene, t));
        }
    }

    public void logInfo(String message) {
        if (logging != null) {
            logging.logToOutput(message);
        }
    }

    public void logError(String message) {
        if (logging != null) {
            logging.logToError(message);
        } else {
            logStaticError(message);
        }
    }

    public void logError(String scene, Throwable t) {
        if (logging != null) {
            logging.logToError(formatThrowable(scene, t));
        } else {
            logStaticError(scene, t);
        }
    }

    private static String formatThrowable(String scene, Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append("[RouteVulScan] ").append(scene);
        if (t != null) {
            sb.append(" | ").append(t.getClass().getName());
            if (t.getMessage() != null && !t.getMessage().trim().isEmpty()) {
                sb.append(": ").append(t.getMessage().trim());
            }
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            t.printStackTrace(pw);
            pw.flush();
            String[] lines = sw.toString().split("\\R");
            int limit = Math.min(lines.length, 8);
            for (int i = 0; i < limit; i++) {
                sb.append(System.lineSeparator()).append(lines[i]);
            }
        }
        return sb.toString();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            if (!responseReceived.toolSource().isFromTool(ToolType.EXTENSIONS)) {
                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(), responseReceived);
                handlePassiveCandidate(requestResponse, "HTTP");
            }
        } catch (Throwable t) {
            logError("处理 HTTP 响应失败", t);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    public void handlePassiveCandidate(HttpRequestResponse requestResponse, String source) {
        if (!on_off || requestResponse == null || requestResponse.request() == null) {
            return;
        }
        try {
            if (Host_txtfield == null) {
                logError("被动扫描未启动：Host 过滤框尚未初始化。");
                return;
            }
            String host = requestResponse.httpService().host();
            String re = Host_txtfield.getText().replace(".", "\\.").replace("*", ".*?");
            Pattern pattern = Pattern.compile(re);
            Matcher matcher = pattern.matcher(host);
            if (!matcher.find()) {
                return;
            }
            String normalizedUrl = urlC.RemoveUrlParameterValue(requestResponse.request().url());
            String method = requestResponse.request().method();
            if (urlC.check(method, normalizedUrl)) {
                return;
            }
            urlC.addMethodAndUrl(method, normalizedUrl);
            String rootUrl = serviceBaseUrl(requestResponse.request());
            try {
                domainNameRepeat.add(rootUrl);
            } catch (Throwable t) {
                logError("记录域名去重失败: " + rootUrl, t);
            }
            ensureThreadPool();
            new vulscan(this, requestResponse, null, source);
        } catch (Throwable t) {
            logError("触发被动扫描失败 [" + source + "]", t);
        }
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = collectSelectedRequestResponses(event);
        if (selected.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem scan = new JMenuItem("发送到 RouteVulScan");
        scan.addActionListener(new ManualScanAction(this, selected, false));

        JMenuItem scanWithHeaders = new JMenuItem("发送到 RouteVulScan 并携带请求头");
        scanWithHeaders.addActionListener(new ManualScanAction(this, selected, true));

        List<Component> items = new ArrayList<Component>();
        items.add(scan);
        items.add(scanWithHeaders);
        return items;
    }

    private List<HttpRequestResponse> collectSelectedRequestResponses(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<HttpRequestResponse>();
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            selected.add(editor.requestResponse());
        }
        if (event.selectedRequestResponses() != null) {
            selected.addAll(event.selectedRequestResponses());
        }
        return selected;
    }

    public void startManualScan(List<HttpRequestResponse> selected, boolean customHeaders) {
        if (selected == null || selected.isEmpty()) {
            logError("主动扫描失败：未选中任何请求。");
            return;
        }
        if (!customHeaders) {
            for (HttpRequestResponse requestResponse : selected) {
                new vulscan(this, requestResponse, null, "手动发送");
            }
            return;
        }
        showHeaderDialog(selected);
    }

    private void showHeaderDialog(List<HttpRequestResponse> selected) {
        HttpRequest baseRequest = selected.get(0).request();
        JTextArea textArea = new JTextArea(12, 60);
        StringBuilder headerText = new StringBuilder();
        for (HttpHeader header : baseRequest.headers()) {
            headerText.append(header.toString()).append('\n');
        }
        textArea.setText(headerText.toString());

        int result = JOptionPane.showConfirmDialog(
                tags != null ? tags.getUiComponent() : null,
                new JScrollPane(textArea),
                "自定义请求头",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        List<String> lines = parseHeaderLines(textArea.getText());
        if (lines == null) {
            prompt(null, "请求头格式不正确。");
            return;
        }

        for (HttpRequestResponse requestResponse : selected) {
            try {
                HttpRequest request = applyCustomHeaders(requestResponse.request(), lines);
                new vulscan(this, requestResponse, request, "手动发送");
            } catch (Throwable t) {
                logError("应用自定义请求头失败", t);
            }
        }
    }

    public HttpRequest applyCarryHeaders(HttpRequest request, List<HttpHeader> carryHeaders) {
        HttpRequest updated = request;
        for (HttpHeader header : carryHeaders) {
            String name = header.name();
            if ("Content-Length".equalsIgnoreCase(name) || "Transfer-Encoding".equalsIgnoreCase(name)) {
                continue;
            }
            updated = updated.withUpdatedHeader(name, header.value());
        }
        return updated;
    }

    public HttpRequest applyCustomHeaders(HttpRequest request, List<String> headerLines) {
        HttpRequest updated = request;
        for (String line : headerLines) {
            int splitIndex = line.indexOf(':');
            if (splitIndex <= 0) {
                continue;
            }
            String name = line.substring(0, splitIndex).trim();
            String value = line.substring(splitIndex + 1).trim();
            updated = updated.withUpdatedHeader(name, value);
        }
        return updated;
    }

    public static List<String> parseHeaderLines(String headerText) {
        if (headerText == null || headerText.trim().isEmpty()) {
            return null;
        }
        List<String> rows = new ArrayList<String>();
        for (String row : headerText.split("\\R")) {
            if (!row.trim().isEmpty()) {
                rows.add(row.trim());
            }
        }
        return rows.isEmpty() ? null : rows;
    }

    public String serviceBaseUrl(HttpRequest request) throws MalformedURLException {
        URL url = new URL(request.url());
        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
    }

    public void prompt(Component component, String message) {
        if (component == null && this.tags != null) {
            component = this.tags.getUiComponent();
        }
        JOptionPane.showMessageDialog(component, message);
    }
}

class ManualScanAction implements ActionListener {
    private final BurpExtender burp;
    private final List<HttpRequestResponse> selected;
    private final boolean customHeaders;

    ManualScanAction(BurpExtender burp, List<HttpRequestResponse> selected, boolean customHeaders) {
        this.burp = burp;
        this.selected = selected;
        this.customHeaders = customHeaders;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        burp.startManualScan(selected, customHeaders);
    }
}
