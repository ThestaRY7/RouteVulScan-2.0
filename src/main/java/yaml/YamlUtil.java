package yaml;

import burp.BurpExtender;
import burp.I18n;
import func.RuleDownloadTask;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class YamlUtil {
    private static final AtomicBoolean RULE_DOWNLOAD_RUNNING = new AtomicBoolean(false);
    private static final ExecutorService RULE_DOWNLOAD_EXECUTOR = Executors.newSingleThreadExecutor(new ThreadFactory() {
        private final AtomicInteger index = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "RouteVulScan-rule-download-" + index.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        }
    });

    public static Map<String, Object> defaultYamlData() {
        Map<String, Object> data = new HashMap<String, Object>();
        data.put("Load_List", new ArrayList<Map<String, Object>>());
        return data;
    }

    public static void init_Yaml(BurpExtender burp, JPanel one) {
        if (!RULE_DOWNLOAD_RUNNING.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                    one,
                    burp.t("rules.updateInProgress"),
                    burp.t("dialog.info"),
                    JOptionPane.INFORMATION_MESSAGE
            ));
            return;
        }
        RULE_DOWNLOAD_EXECUTOR.submit(new RuleDownloadTask(burp, one, RULE_DOWNLOAD_RUNNING));
    }

    public static void shutdownRuleDownloadExecutor() {
        RULE_DOWNLOAD_EXECUTOR.shutdownNow();
    }

    public static Map<String, Object> readYaml(String file_path) {
        File file = new File(file_path);
        Map<String, Object> data = defaultYamlData();
        if (!file.exists()) {
            writeYaml(data, file_path);
            return data;
        }
        try (InputStream inputStream = new FileInputStream(file)) {
            Yaml yaml = new Yaml();
            Object loaded = yaml.load(inputStream);
            if (loaded instanceof Map) {
                data.put("Load_List", ((Map<String, Object>) loaded).get("Load_List"));
            }
            if (!(data.get("Load_List") instanceof List)) {
                data.put("Load_List", new ArrayList<Map<String, Object>>());
            }
        } catch (Throwable e) {
            BurpExtender.logStaticError(I18n.t("log.readYamlFailed", file_path), e);
        }
        return data;
    }

    public static void writeYaml(Map<String, Object> data, String filePath) {
        Yaml yaml = new Yaml();
        Map<String, Object> saveData = defaultYamlData();
        if (data != null && data.get("Load_List") instanceof List) {
            saveData.put("Load_List", data.get("Load_List"));
        }
        if (!(saveData.get("Load_List") instanceof List)) {
            saveData.put("Load_List", new ArrayList<Map<String, Object>>());
        }
        try (PrintWriter writer = new PrintWriter(new File(filePath))) {
            yaml.dump(saveData, writer);
        } catch (FileNotFoundException e) {
            BurpExtender.logStaticError(I18n.t("log.writeYamlFailed", filePath), e);
        }
    }

    public static void removeYaml(String id, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        ArrayList<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (!zidian.get("id").toString().equals(id)) {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
        save.put("Load_List", List2);
        YamlUtil.writeYaml(save, filePath);
    }

    public static void updateYaml(Map<String, Object> up, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        List<Map<String, Object>> List2 = new ArrayList<Map<String, Object>>();
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(up.get("id").toString())) {
                List2.add(up);
            } else {
                List2.add(zidian);
            }
        }
        Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
        save.put("Load_List", List2);
        YamlUtil.writeYaml(save, filePath);

    }

    public static void addYaml(Map<String, Object> add, String filePath) {
        Map<String, Object> Yaml_Map = YamlUtil.readYaml(filePath);
        List<Map<String, Object>> List1 = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        int panduan = 0;
        for (Map<String, Object> zidian : List1) {
            if (zidian.get("id").toString().equals(add.get("id").toString())) {
                panduan += 1;
            }
        }
        if (panduan == 0) {
            Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
            List1.add(add);
            save.put("Load_List", List1);
            YamlUtil.writeYaml(save, filePath);
        }

    }

    public static Map<String, Object> readStrYaml(String str){
        Yaml yaml = new Yaml();
        Map<String, Object> data = defaultYamlData();
        Object loaded = yaml.load(str);
        if (loaded instanceof Map) {
            data.put("Load_List", ((Map<String, Object>) loaded).get("Load_List"));
        }
        if (!(data.get("Load_List") instanceof List)) {
            data.put("Load_List", new ArrayList<Map<String, Object>>());
        }
        return data;
    }


    public static void MergerUpdateYamlFunc(Map<String, Object> newYaml){
        Map<String, Object> oldYaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        List<Map<String, Object>> oldYamlList = (List<Map<String, Object>>)oldYaml.get("Load_List");
        List<Map<String, Object>> newYamlList = (List<Map<String, Object>>)newYaml.get("Load_List");
        for (Map<String, Object> i : newYamlList){
            if (!YamlUtil.inYamlList(oldYamlList,i)){
                int id = 0;
                for (Map<String, Object> zidian : (List<Map<String, Object>>)YamlUtil.readYaml(BurpExtender.Yaml_Path).get("Load_List")) {
                    if ((int) zidian.get("id") > id) {
                        id = (int) zidian.get("id");
                    }
                }
                id += 1;
                i.remove("id");
                i.put("id",id);
                YamlUtil.addYaml(i,BurpExtender.Yaml_Path);
            }
        }
        Map<String, Object> save = (Map<String, Object>) new HashMap<String, Object>();
        save.put("Load_List", (List<Map<String, Object>>) YamlUtil.readYaml(BurpExtender.Yaml_Path).get("Load_List"));
        YamlUtil.writeYaml(save,BurpExtender.Yaml_Path);



    }

    public static boolean inYamlList(List<Map<String, Object>> mapList,Map<String, Object> oneMap){
        for (Map<String, Object> i : mapList){
            if (YamlUtil.ifmapEqual(i,oneMap)){
                return true;
            }
        }
        return false;

    }

    public static boolean ifmapEqual(Map<String, Object> i, Map<String, Object> oneMap){
        boolean mapEqual = true;
        for (String key : i.keySet()){
            if (!key.equals("loaded") && !key.equals("id") && !key.equals("type")){
                if (!i.get(key).equals(oneMap.get(key))){
                    mapEqual = false;
                    break;
                }
            }
        }
        return mapEqual;
    }



}
