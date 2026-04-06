package burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import yaml.YamlUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class Bfunc {

    public static Map<String, View> Get_Views(BurpExtender burp) {
        Map<String, View> views = new Hashtable<String, View>();
        Map<String, Object> jieguo = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        List<Map<String, Object>> rule_list = (List<Map<String, Object>>) jieguo.get("Load_List");
        for (Map<String, Object> zidian : rule_list) {
            String type = (String) zidian.get("type");
            String id = String.valueOf(zidian.get("id"));
            String name = (String) zidian.get("name");
            String url = (String) zidian.get("url");
            String re = (String) zidian.get("re");
            String info = (String) zidian.get("info");
            String state = (String) zidian.get("state");
            String method = (String) zidian.get("method");
            boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));

            if (type == null || type.trim().isEmpty()) {
                zidian.put("type", "default");
                YamlUtil.updateYaml(zidian, BurpExtender.Yaml_Path);
                type = "default";
            }

            if (!views.containsKey(type)) {
                views.put(type, new View(burp));
            }
            views.get(type).log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
        }
        return views;
    }

    public static void show_yaml(BurpExtender burp) {
        burp.views = Get_Views(burp);
        burp.Config_l.ruleTabbedPane.removeAll();
        for (String key : burp.views.keySet()) {
            burp.Config_l.ruleTabbedPane.addTab(key, burp.views.get(key).Get_View());
        }
        burp.Config_l.afterRulesReload();
    }

    public static Collection<Integer> StatusCodeProc(String state) {
        Collection<Integer> stateList = new ArrayList<Integer>();
        if (state.length() != 3 && (state.contains(",") || state.contains("-"))) {
            if (state.contains(",")) {
                String[] states = state.split(",");
                for (String oneState : states) {
                    if (oneState.contains("-")) {
                        String[] parts = oneState.split("-");
                        int start = Integer.parseInt(parts[0]);
                        int end = Integer.parseInt(parts[1]);
                        for (int i = start; i <= end; i++) {
                            stateList.add(i);
                        }
                    } else if (oneState.length() == 3) {
                        stateList.add(Integer.valueOf(oneState));
                    }
                }
            } else {
                String[] parts = state.split("-");
                int start = Integer.parseInt(parts[0]);
                int end = Integer.parseInt(parts[1]);
                for (int i = start; i <= end; i++) {
                    stateList.add(i);
                }
            }
        } else {
            stateList.add(Integer.valueOf(state));
        }
        return stateList;
    }

    public static String ProcTemplateLanguag(String template, HttpRequestResponse requestResponse, boolean escape) {
        if (template == null) {
            return "";
        }
        if (!(template.contains("{{") && template.contains("}}"))) {
            return template;
        }

        String marking = template.substring(template.indexOf("{{"), template.lastIndexOf("}}") + 2);
        String markingContent = marking.replace("{{", "").replace("}}", "").toLowerCase();
        String[] parts = markingContent.split("\\.");
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.hasResponse() ? requestResponse.response() : null;
        HttpService httpService = requestResponse.httpService();

        switch (parts[0]) {
            case "request":
                if (parts.length < 2) {
                    return template;
                }
                switch (parts[1]) {
                    case "head":
                        Map<String, String> requestHeaders = Bfunc.ProceHead(request.headers());
                        if (parts.length > 3 && "host".equals(parts[2])) {
                            if ("main".equals(parts[3])) {
                                return replaceOn(template, marking, Bfunc.AnalyHost(requestHeaders.get("host"), "main"), escape);
                            }
                            if ("name".equals(parts[3])) {
                                return replaceOn(template, marking, Bfunc.AnalyHost(requestHeaders.get("host"), "name"), escape);
                            }
                        }
                        return parts.length > 2 ? replaceOn(template, marking, requestHeaders.get(parts[2]), escape) : template;
                    case "method":
                        return replaceOn(template, marking, request.method(), escape);
                    case "path":
                        return replaceOn(template, marking, request.pathWithoutQuery().replaceFirst("^/", ""), escape);
                    case "url":
                        return replaceOn(template, marking, request.url(), escape);
                    case "protocol":
                        return replaceOn(template, marking, httpService.secure() ? "https" : "http", escape);
                    case "port":
                        return replaceOn(template, marking, String.valueOf(httpService.port()), escape);
                    default:
                        return template;
                }
            case "response":
                if (response == null || parts.length < 2) {
                    return template;
                }
                switch (parts[1]) {
                    case "head":
                        Map<String, String> responseHeaders = Bfunc.ProceHead(response.headers());
                        return parts.length > 2 ? replaceOn(template, marking, responseHeaders.get(parts[2]), escape) : template;
                    case "status":
                        return replaceOn(template, marking, String.valueOf(response.statusCode()), escape);
                    default:
                        return template;
                }
            default:
                return template;
        }
    }

    private static String replaceOn(String url, String one, String two, Boolean escape) {
        if (two != null) {
            return url.replace(one, escape ? Pattern.quote(two) : two);
        }
        return url.replace(one, "");
    }

    public static String AnalyHost(String host, String mode) {
        String domain = host.split(":")[0];
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            return host;
        }
        String[] parts = domain.split("\\.");
        if (parts.length < 2) {
            return domain;
        }

        if (parts[parts.length - 1].equals("cn") && parts.length >= 3 && parts[parts.length - 2].equals("com")) {
            if ("main".equals(mode)) {
                return parts[parts.length - 3] + "." + parts[parts.length - 2] + "." + parts[parts.length - 1];
            }
            if ("name".equals(mode)) {
                return parts[parts.length - 3];
            }
        } else {
            if ("main".equals(mode)) {
                return parts[parts.length - 2] + "." + parts[parts.length - 1];
            }
            if ("name".equals(mode)) {
                return parts[parts.length - 2];
            }
        }
        return domain;
    }

    public static Map<String, String> ProceHead(List<HttpHeader> headers) {
        Map<String, String> headmap = new HashMap<String, String>();
        for (HttpHeader header : headers) {
            headmap.put(header.name().toLowerCase(), header.value());
        }
        return headmap;
    }
}
