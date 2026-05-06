package func;

import burp.Bfunc;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class threads implements Runnable {
    private final Map<String, Object> zidian;
    private final vulscan vul;
    private final HttpRequestResponse newHttpRequestResponse;
    private final List<burp.api.montoya.http.message.HttpHeader> heads;

    public threads(Map<String, Object> zidian, vulscan vul, HttpRequestResponse newHttpRequestResponse, List<burp.api.montoya.http.message.HttpHeader> heads) {
        this.zidian = zidian;
        this.vul = vul;
        this.newHttpRequestResponse = newHttpRequestResponse;
        this.heads = heads;
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
            go(this.zidian, this.vul, this.newHttpRequestResponse, this.heads);
        } finally {
            if (counted && !vul.isCancelled()) {
                vul.burp.noteTaskFinished();
            }
        }
    }

    private static void go(Map<String, Object> zidian, vulscan vul, HttpRequestResponse source, List<burp.api.montoya.http.message.HttpHeader> heads) {
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

        HttpRequest request = HttpRequest.httpRequestFromUrl(url.toString());
        if (vul.burp.Carry_head) {
            request = vul.burp.applyCarryHeaders(request, heads);
        }
        if ("POST".equalsIgnoreCase(String.valueOf(zidian.get("method")))) {
            request = request.withMethod("POST");
        }

        HttpRequestResponse response = vul.burp.api.http().sendRequest(request);
        if (response == null || !response.hasResponse()) {
            return;
        }

        matchResponse(vul, name, info, re, states, response);
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
