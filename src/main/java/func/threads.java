package func;

import burp.Bfunc;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class threads implements Runnable {
    private static final int MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024;
    private static final long REGEX_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(2);

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
        } catch (Throwable t) {
            String ruleName = zidian == null ? "" : String.valueOf(zidian.get("name"));
            vul.burp.logError(vul.burp.t("log.ruleExecutionFailed", ruleName), t);
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

        boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));
        if (!loaded) {
            return;
        }

        String name = String.valueOf(zidian.get("name"));
        String urll = Bfunc.ProcTemplateLanguag(String.valueOf(zidian.get("url")), source, false);
        String re = Bfunc.ProcTemplateLanguag(String.valueOf(zidian.get("re")), source, true);
        String info = String.valueOf(zidian.get("info"));
        Collection<Integer> states = Bfunc.StatusCodeProc(String.valueOf(zidian.get("state")));

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

        // 记录真实的请求发送区间，结果表刷新时直接复用该时间，不再临时重算。
        long requestStartedAt = System.currentTimeMillis();
        HttpRequestResponse response = vul.burp.sendScanRequest(request);
        long requestCompletedAt = System.currentTimeMillis();
        if (response == null || !response.hasResponse()) {
            return;
        }

        matchResponse(vul, name, info, re, states, response, requestStartedAt, requestCompletedAt);
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

    private static boolean matchResponse(
            vulscan vul,
            String name,
            String info,
            String re,
            Collection<Integer> states,
            HttpRequestResponse response,
            long requestStartedAt,
            long requestCompletedAt
    ) {
        if (vul.isCancelled()) {
            return false;
        }
        int statusCode = response.response().statusCode();
        if (!states.contains(statusCode)) {
            return false;
        }
        int responseBodyBytes = response.response().body().length();
        if (responseBodyBytes > MAX_RESPONSE_BODY_BYTES) {
            vul.burp.logError(vul.burp.t(
                    "log.responseTooLarge",
                    name,
                    responseBodyBytes,
                    MAX_RESPONSE_BODY_BYTES
            ));
            return false;
        }
        Pattern reRule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
        String responseText = response.response().bodyToString();
        try {
            if (!findWithTimeout(reRule, responseText, REGEX_TIMEOUT_NANOS)) {
                return false;
            }
        } catch (RegexTimeoutException e) {
            vul.burp.noteTimeout();
            vul.burp.logError(vul.burp.t("log.regexTimeout", name));
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
                    response,
                    requestStartedAt,
                    requestCompletedAt
            );
        }
        return true;
    }

    /** 在字符访问阶段检查截止时间，阻止灾难性回溯无限占用扫描线程。 */
    static boolean findWithTimeout(Pattern pattern, String input, long timeoutNanos) {
        long deadline = System.nanoTime() + timeoutNanos;
        Matcher matcher = pattern.matcher(new DeadlineCharSequence(input, deadline));
        return matcher.find();
    }

    /** 为 Java 正则提供带截止时间的只读字符序列。 */
    private static final class DeadlineCharSequence implements CharSequence {
        private final CharSequence delegate;
        private final long deadlineNanos;

        /** 保存底层文本与所有切片共享的单调时钟截止时间。 */
        private DeadlineCharSequence(CharSequence delegate, long deadlineNanos) {
            this.delegate = delegate;
            this.deadlineNanos = deadlineNanos;
        }

        /** 返回长度；该操作不遍历正文。 */
        @Override
        public int length() {
            return delegate.length();
        }

        /** 每次读取字符前检查取消状态和单调时钟截止时间。 */
        @Override
        public char charAt(int index) {
            if (Thread.currentThread().isInterrupted() || System.nanoTime() - deadlineNanos >= 0) {
                throw new RegexTimeoutException();
            }
            return delegate.charAt(index);
        }

        /** 子序列继承同一个截止时间，防止正则内部切片绕过限制。 */
        @Override
        public CharSequence subSequence(int start, int end) {
            return new DeadlineCharSequence(delegate.subSequence(start, end), deadlineNanos);
        }

        /** 返回底层文本，供诊断使用；匹配过程不会依赖该方法绕过 charAt。 */
        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    /** 标记正则匹配已超过资源边界，不生成昂贵的异常堆栈。 */
    static final class RegexTimeoutException extends RuntimeException {
        /** 超时属于预期控制流，省略堆栈构造以减少扫描线程开销。 */
        @Override
        public synchronized Throwable fillInStackTrace() {
            return this;
        }
    }
}
