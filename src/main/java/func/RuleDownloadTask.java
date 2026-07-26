package func;

import burp.Bfunc;
import burp.BurpExtender;
import yaml.YamlUtil;

import javax.swing.*;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

public class RuleDownloadTask implements Runnable {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(25);
    private static final int MAX_RULE_FILE_BYTES = 2 * 1024 * 1024;
    private static final int MAX_RULE_COUNT = 1_000;
    private static final Set<String> REQUIRED_RULE_KEYS = Set.of(
            "id", "type", "loaded", "name", "method", "url", "re", "info", "state"
    );

    private final BurpExtender burp;
    private final JPanel parent;
    private final AtomicBoolean running;

    public RuleDownloadTask(BurpExtender burp, JPanel parent, AtomicBoolean running) {
        this.burp = burp;
        this.parent = parent;
        this.running = running;
    }

    @Override
    public void run() {
        try {
            Map<String, Object> downloadedRules = downloadRules();
            YamlUtil.MergerUpdateYamlFunc(downloadedRules);
            SwingUtilities.invokeLater(() -> {
                Bfunc.show_yaml(burp);
                showMessage(burp.t("rules.updateSuccess"), JOptionPane.INFORMATION_MESSAGE);
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            burp.logError(burp.t("log.rulesUpdateInterrupted"));
        } catch (RuleDownloadException e) {
            burp.logError(e.getMessage());
            showMessage(e.userMessage(), JOptionPane.ERROR_MESSAGE);
        } catch (Throwable e) {
            burp.logError(burp.t("log.rulesUpdateFailed"), e);
            showMessage(burp.t("rules.updateFailed"), JOptionPane.ERROR_MESSAGE);
        } finally {
            running.set(false);
        }
    }

    /** 下载、限制大小并校验云端规则，任何异常内容都不能进入本地合并流程。 */
    private Map<String, Object> downloadRules() throws IOException, InterruptedException, RuleDownloadException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(downloadUrl()))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        int statusCode = response.statusCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw new RuleDownloadException(
                    burp.t("rules.updateHttpFailed", statusCode),
                    burp.t("rules.updateRequestFailed")
            );
        }

        if (response.body().length > MAX_RULE_FILE_BYTES) {
            throw new RuleDownloadException(
                    burp.t("rules.updateTooLarge", response.body().length, MAX_RULE_FILE_BYTES),
                    burp.t("rules.updateInvalid")
            );
        }

        Map<String, Object> yaml;
        try {
            yaml = YamlUtil.readStrYaml(new String(response.body(), StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new RuleDownloadException(
                    burp.t("rules.updateInvalid"),
                    burp.t("rules.updateInvalid")
            );
        }
        List<Map<String, Object>> ruleList = (List<Map<String, Object>>) yaml.get("Load_List");
        if (ruleList == null || ruleList.isEmpty()) {
            throw new RuleDownloadException(
                    burp.t("rules.updateInvalid"),
                    burp.t("rules.updateInvalid")
            );
        }
        validateRules(ruleList);
        return yaml;
    }

    /** 校验下载规则的字段、方法、状态码和正则，阻止单条脏规则破坏整个 UI。 */
    private void validateRules(List<Map<String, Object>> rules) throws RuleDownloadException {
        if (rules.size() > MAX_RULE_COUNT) {
            throw new RuleDownloadException(
                    burp.t("rules.updateTooManyRules", rules.size(), MAX_RULE_COUNT),
                    burp.t("rules.updateInvalid")
            );
        }
        for (int index = 0; index < rules.size(); index++) {
            Map<String, Object> rule = rules.get(index);
            try {
                if (rule == null || !rule.keySet().containsAll(REQUIRED_RULE_KEYS)) {
                    throw new IllegalArgumentException("missing required fields");
                }
                requireNonBlankString(rule, "type");
                requireNonBlankString(rule, "name");
                String method = requireNonBlankString(rule, "method");
                if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
                    throw new IllegalArgumentException("unsupported method");
                }
                String path = requireNonBlankString(rule, "url");
                if (!path.startsWith("/")) {
                    throw new IllegalArgumentException("path must start with /");
                }
                String regex = requireNonBlankString(rule, "re");
                Pattern.compile(regex);
                requireString(rule, "info");
                Bfunc.StatusCodeProc(requireNonBlankString(rule, "state"));
                if (!(rule.get("loaded") instanceof Boolean)) {
                    throw new IllegalArgumentException("loaded must be boolean");
                }
                Integer.parseInt(String.valueOf(rule.get("id")));
            } catch (IllegalArgumentException e) {
                throw new RuleDownloadException(
                        burp.t("rules.updateInvalidRule", index + 1, e.getMessage()),
                        burp.t("rules.updateInvalid")
                );
            }
        }
    }

    /** 读取必填非空字符串字段。 */
    private String requireNonBlankString(Map<String, Object> rule, String key) {
        String value = requireString(rule, key);
        if (value.isBlank()) {
            throw new IllegalArgumentException(key + " cannot be blank");
        }
        return value;
    }

    /** 读取字符串字段并拒绝隐式类型转换。 */
    private String requireString(Map<String, Object> rule, String key) {
        Object value = rule.get(key);
        if (!(value instanceof String)) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        return (String) value;
    }

    private String downloadUrl() {
        return BurpExtender.Download_Yaml_protocol + "://"
                + BurpExtender.Download_Yaml_host
                + BurpExtender.Download_Yaml_file;
    }

    private void showMessage(String message, int messageType) {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                parent,
                message,
                burp.t(messageType == JOptionPane.ERROR_MESSAGE ? "dialog.error" : "dialog.info"),
                messageType
        ));
    }

    private static class RuleDownloadException extends Exception {
        private final String userMessage;

        private RuleDownloadException(String logMessage, String userMessage) {
            super(logMessage);
            this.userMessage = userMessage;
        }

        private String userMessage() {
            return userMessage;
        }
    }
}
