package utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * 保存请求方法与去参数值 URL 的有界去重窗口，防止 Burp 长时间运行时记录无限增长。
 */
public class UrlRepeat {
    private final BoundedSet<String> methodAndUrls;

    /** 创建指定容量的 URL 去重窗口。 */
    public UrlRepeat(int maximumSize) {
        this.methodAndUrls = new BoundedSet<String>(maximumSize);
    }

    /** 清空 URL 去重记录。 */
    public void clear() {
        methodAndUrls.clear();
    }

    /** 添加合法的请求方法与 URL 组合。 */
    public void addMethodAndUrl(String method, String url) {
        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException("Request method cannot be empty");
        }
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Url cannot be empty");
        }
        methodAndUrls.add(key(method, url));
    }

    /** 判断请求方法与 URL 组合是否已经处理。 */
    public boolean check(String method, String url) {
        return methodAndUrls.contains(key(method, url));
    }

    /**
     * 保留参数名但清空参数值，避免不同业务值重复触发同一路径扫描。
     */
    public String RemoveUrlParameterValue(String url) {
        try {
            new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL: " + url, e);
        }

        int queryStart = url.indexOf('?');
        if (queryStart < 0) {
            return url;
        }
        int fragmentStart = url.indexOf('#', queryStart);
        String query = url.substring(queryStart + 1, fragmentStart < 0 ? url.length() : fragmentStart);
        if (query.isEmpty()) {
            return url;
        }
        String normalizedQuery = Arrays.stream(query.split("&", -1))
                .map(parameter -> parameter.split("=", 2)[0] + "=")
                .collect(Collectors.joining("&"));
        String fragment = fragmentStart < 0 ? "" : url.substring(fragmentStart);
        return url.substring(0, queryStart + 1) + normalizedQuery + fragment;
    }

    /** 构造不产生歧义的请求去重键。 */
    private String key(String method, String url) {
        return method + "\n" + url;
    }
}
