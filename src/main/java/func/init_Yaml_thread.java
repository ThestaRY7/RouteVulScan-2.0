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
                JOptionPane.showMessageDialog(one, "规则更新成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            } else {
                burp.logError("在线更新规则失败：未获取到响应，请检查 Burp 代理或网络连通性。");
                JOptionPane.showMessageDialog(one, "请求失败，请检查 Burp 代理或网络连接", "错误", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Throwable e) {
            burp.logError("在线更新规则失败", e);
            JOptionPane.showMessageDialog(one, "规则更新失败，详细错误请查看 Burp Errors 面板", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}
