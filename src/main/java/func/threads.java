package func;

import burp.Bfunc;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class threads implements Runnable {
    private final Map<String, Object> zidian;
    private final vulscan vul;
    private final HttpRequestResponse newHttpRequestResponse;

    public threads(Map<String, Object> zidian, vulscan vul, HttpRequestResponse newHttpRequestResponse) {
        this.zidian = zidian;
        this.vul = vul;
        this.newHttpRequestResponse = newHttpRequestResponse;
    }

    @Override
    public void run() {
        if (vul.isCancelled()) {
            return;
        }
        boolean counted = false;
        try {
            vul.burp.noteTaskStarted();
            counted = true;
            go(this.zidian, this.vul, this.newHttpRequestResponse);
        } finally {
            if (counted && !vul.isCancelled()) {
                vul.burp.noteTaskFinished();
            }
        }
    }

    private static void go(Map<String, Object> zidian, vulscan vul, HttpRequestResponse source) {
        if (vul.isCancelled()) {
            return;
        }

        String name = (String) zidian.get("name");
        boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));
        String urll = Bfunc.ProcTemplateLanguag((String) zidian.get("url"), source, false);
        String re = Bfunc.ProcTemplateLanguag((String) zidian.get("re"), source, true);
        String info = (String) zidian.get("info");
        Collection<Integer> states = Bfunc.StatusCodeProc((String) zidian.get("state"));

        if (!loaded) {
            return;
        }

        URL url;
        try {
            URL seedUrl = new URL(source.request().url());
            url = new URL(seedUrl.getProtocol(), seedUrl.getHost(), seedUrl.getPort(), String.valueOf(vul.Path_record) + urll);
        } catch (MalformedURLException e) {
            vul.burp.logError(vul.burp.t("log.buildScanUrlFailed"), e);
            return;
        }

        String ruleMethod = String.valueOf(zidian.get("method"));
        HttpRequest request = buildScanRequest(vul, url, ruleMethod);

        HttpRequestResponse response = vul.burp.api.http().sendRequest(request);
        if (response == null || !response.hasResponse()) {
            return;
        }

        matchResponse(vul, name, info, re, states, response);
    }

    private static HttpRequest buildScanRequest(vulscan vul, URL url, String ruleMethod) {
        HttpRequest request;
        if (vul.shouldCarryHeaders()) {
            // 携带请求头时以原始请求为模板，仅替换扫描路径，避免丢失 Cookie、认证头和业务自定义头。
            request = vul.seedRequest().withPath(url.getFile());
        } else {
            request = HttpRequest.httpRequestFromUrl(url.toString());
        }

        if ("POST".equalsIgnoreCase(ruleMethod)) {
            return request.withMethod("POST");
        }
        return request.withMethod("GET");
    }

    private static boolean matchResponse(vulscan vul, String name, String info, String re, Collection<Integer> states, HttpRequestResponse response) {
        if (vul.isCancelled()) {
            return false;
        }
        int statusCode = response.response().statusCode();
        if (!states.contains(statusCode)) {
            return false;
        }
        Pattern reRule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
        String responseText = response.response().bodyToString();
        Matcher pipe = reRule.matcher(responseText);
        if (!pipe.find()) {
            return false;
        }
        synchronized (vul) {
            vul.burp.noteMatchFound();
            vulscan.ir_add(
                    vul.burp.tags,
                    name,
                    response.request().method(),
                    response.request().url(),
                    statusCode + " ",
                    info,
                    String.valueOf(responseText.length()),
                    response
            );
        }
        return true;
    }
}
