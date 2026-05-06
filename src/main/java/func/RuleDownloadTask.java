package func;

import burp.Bfunc;
import burp.BurpExtender;
import yaml.YamlUtil;

import javax.swing.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class RuleDownloadTask implements Runnable {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(25);

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

    private Map<String, Object> downloadRules() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(downloadUrl()))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        int statusCode = response.statusCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw new RuleDownloadException(
                    burp.t("rules.updateHttpFailed", statusCode),
                    burp.t("rules.updateRequestFailed")
            );
        }

        Map<String, Object> yaml = YamlUtil.readStrYaml(response.body());
        List<Map<String, Object>> ruleList = (List<Map<String, Object>>) yaml.get("Load_List");
        if (ruleList == null || ruleList.isEmpty()) {
            throw new RuleDownloadException(
                    burp.t("rules.updateInvalid"),
                    burp.t("rules.updateInvalid")
            );
        }
        return yaml;
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
