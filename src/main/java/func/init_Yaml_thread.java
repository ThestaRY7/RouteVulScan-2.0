package func;

import burp.Bfunc;
import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import yaml.YamlUtil;

import javax.swing.*;
import java.util.Map;

public class init_Yaml_thread extends Thread {
    private final BurpExtender burp;
    private final JPanel one;

    public init_Yaml_thread(BurpExtender burp, JPanel one) {
        this.burp = burp;
        this.one = one;
    }

    public void run() {
        try {
            String url = BurpExtender.Download_Yaml_protocol + "://" + BurpExtender.Download_Yaml_host + BurpExtender.Download_Yaml_file;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse yamlResponse = this.burp.api.http().sendRequest(request);

            if (yamlResponse != null && yamlResponse.hasResponse()) {
                String responseBody = yamlResponse.response().bodyToString();
                Map<String, Object> newYaml = YamlUtil.readStrYaml(responseBody);
                YamlUtil.MergerUpdateYamlFunc(newYaml);
                Bfunc.show_yaml(burp);
                JOptionPane.showMessageDialog(one, burp.t("rules.updateSuccess"), burp.t("dialog.info"), JOptionPane.INFORMATION_MESSAGE);
            } else {
                burp.logError(burp.t("rules.updateNoResponse"));
                JOptionPane.showMessageDialog(one, burp.t("rules.updateRequestFailed"), burp.t("dialog.error"), JOptionPane.ERROR_MESSAGE);
            }
        } catch (Throwable e) {
            burp.logError(burp.t("log.rulesUpdateFailed"), e);
            JOptionPane.showMessageDialog(one, burp.t("rules.updateFailed"), burp.t("dialog.error"), JOptionPane.ERROR_MESSAGE);
        }
    }
}
