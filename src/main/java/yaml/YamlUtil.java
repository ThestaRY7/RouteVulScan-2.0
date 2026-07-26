package yaml;

import burp.BurpExtender;
import burp.I18n;
import func.RuleDownloadTask;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class YamlUtil {
    private static final Object YAML_FILE_LOCK = new Object();
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

    /** 创建始终包含规则列表的默认 YAML 数据，避免调用方处理空根节点。 */
    public static Map<String, Object> defaultYamlData() {
        Map<String, Object> data = new LinkedHashMap<String, Object>();
        data.put("Load_List", new ArrayList<Map<String, Object>>());
        return data;
    }

    /** 在独立守护线程中下载规则，同一时刻只允许一个更新任务运行。 */
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

    /** 插件卸载时停止规则下载线程，避免扩展卸载后仍保留后台任务。 */
    public static void shutdownRuleDownloadExecutor() {
        RULE_DOWNLOAD_EXECUTOR.shutdownNow();
    }

    /**
     * 容错读取本地规则。解析失败时只返回空视图并保留原文件，禁止用默认数据覆盖损坏文件。
     */
    public static Map<String, Object> readYaml(String filePath) {
        synchronized (YAML_FILE_LOCK) {
            return readYamlInternal(filePath, false);
        }
    }

    /**
     * 使用 UTF-8 和同目录临时文件原子写入规则，防止进程中断留下半个 YAML 文件。
     */
    public static boolean writeYaml(Map<String, Object> data, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                writeYamlInternal(data, filePath);
                return true;
            } catch (IOException | RuntimeException e) {
                BurpExtender.logStaticError(I18n.t("log.writeYamlFailed", filePath), e);
                return false;
            }
        }
    }

    /** 删除指定唯一 ID 的一条规则；读取失败时终止操作并保留原文件。 */
    public static boolean removeYaml(String id, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> yamlMap = readYamlInternal(filePath, true);
                List<Map<String, Object>> rules = ruleList(yamlMap);
                boolean removed = false;
                List<Map<String, Object>> retainedRules = new ArrayList<Map<String, Object>>();
                for (Map<String, Object> rule : rules) {
                    if (!removed && Objects.equals(String.valueOf(rule.get("id")), id)) {
                        removed = true;
                    } else {
                        retainedRules.add(rule);
                    }
                }
                if (removed) {
                    Map<String, Object> saveData = defaultYamlData();
                    saveData.put("Load_List", retainedRules);
                    writeYamlInternal(saveData, filePath);
                }
                return removed;
            } catch (IOException | RuntimeException e) {
                logMutationFailure(filePath, e);
                return false;
            }
        }
    }

    /** 更新指定唯一 ID 的一条规则；重复 ID 会在读取阶段被确定性修复。 */
    public static boolean updateYaml(Map<String, Object> updatedRule, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> yamlMap = readYamlInternal(filePath, true);
                List<Map<String, Object>> rules = ruleList(yamlMap);
                String updatedId = String.valueOf(updatedRule.get("id"));
                boolean updated = false;
                List<Map<String, Object>> savedRules = new ArrayList<Map<String, Object>>();
                for (Map<String, Object> rule : rules) {
                    if (!updated && Objects.equals(String.valueOf(rule.get("id")), updatedId)) {
                        savedRules.add(new LinkedHashMap<String, Object>(updatedRule));
                        updated = true;
                    } else {
                        savedRules.add(rule);
                    }
                }
                if (updated) {
                    Map<String, Object> saveData = defaultYamlData();
                    saveData.put("Load_List", savedRules);
                    writeYamlInternal(saveData, filePath);
                }
                return updated;
            } catch (IOException | RuntimeException e) {
                logMutationFailure(filePath, e);
                return false;
            }
        }
    }

    /** 新增规则；缺失、非法或冲突的 ID 会被替换为下一个可用正整数。 */
    public static boolean addYaml(Map<String, Object> addedRule, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> yamlMap = readYamlInternal(filePath, true);
                List<Map<String, Object>> rules = ruleList(yamlMap);
                Map<String, Object> ruleToAdd = new LinkedHashMap<String, Object>(addedRule);
                Set<Integer> usedIds = collectRuleIds(rules);
                Integer requestedId = parsePositiveRuleId(ruleToAdd.get("id"));
                if (requestedId == null || usedIds.contains(requestedId)) {
                    ruleToAdd.put("id", nextRuleId(usedIds));
                } else {
                    ruleToAdd.put("id", requestedId);
                }
                rules.add(ruleToAdd);
                writeYamlInternal(yamlMap, filePath);
                addedRule.put("id", ruleToAdd.get("id"));
                return true;
            } catch (IOException | RuntimeException e) {
                logMutationFailure(filePath, e);
                return false;
            }
        }
    }

    /** 将指定规则组一次性重命名并原子写入，避免逐条保存产生部分更新。 */
    public static boolean renameRuleGroup(String oldType, String newType, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> yamlMap = readYamlInternal(filePath, true);
                boolean changed = false;
                for (Map<String, Object> rule : ruleList(yamlMap)) {
                    if (Objects.equals(String.valueOf(rule.get("type")), oldType)) {
                        rule.put("type", newType);
                        changed = true;
                    }
                }
                if (changed) {
                    writeYamlInternal(yamlMap, filePath);
                }
                return changed;
            } catch (IOException | RuntimeException e) {
                logMutationFailure(filePath, e);
                return false;
            }
        }
    }

    /** 将指定规则组一次性删除并原子写入，避免逐条删除产生部分更新。 */
    public static boolean removeRuleGroup(String type, String filePath) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> yamlMap = readYamlInternal(filePath, true);
                List<Map<String, Object>> rules = ruleList(yamlMap);
                List<Map<String, Object>> retainedRules = new ArrayList<Map<String, Object>>();
                for (Map<String, Object> rule : rules) {
                    if (!Objects.equals(String.valueOf(rule.get("type")), type)) {
                        retainedRules.add(rule);
                    }
                }
                if (retainedRules.size() == rules.size()) {
                    return false;
                }
                yamlMap.put("Load_List", retainedRules);
                writeYamlInternal(yamlMap, filePath);
                return true;
            } catch (IOException | RuntimeException e) {
                logMutationFailure(filePath, e);
                return false;
            }
        }
    }

    /** 安全解析下载得到的 YAML 字符串，只接受 Map 根节点和规则列表。 */
    public static Map<String, Object> readStrYaml(String yamlText) {
        if (yamlText == null) {
            return defaultYamlData();
        }
        Object loaded = newSafeYaml().load(yamlText);
        return normalizeLoadedYaml(loaded);
    }

    /**
     * 将云端新增规则一次性合并到本地，并在持锁状态下执行一次原子写入。
     */
    public static void MergerUpdateYamlFunc(Map<String, Object> newYaml) {
        synchronized (YAML_FILE_LOCK) {
            try {
                Map<String, Object> oldYaml = readYamlInternal(BurpExtender.Yaml_Path, true);
                List<Map<String, Object>> oldRules = ruleList(oldYaml);
                List<Map<String, Object>> newRules = ruleList(newYaml);
                Set<Integer> usedIds = collectRuleIds(oldRules);
                boolean changed = false;
                for (Map<String, Object> newRule : newRules) {
                    if (newRule != null && !inYamlList(oldRules, newRule)) {
                        Map<String, Object> ruleToAdd = new LinkedHashMap<String, Object>(newRule);
                        int id = nextRuleId(usedIds);
                        usedIds.add(id);
                        ruleToAdd.put("id", id);
                        oldRules.add(ruleToAdd);
                        changed = true;
                    }
                }
                if (changed) {
                    writeYamlInternal(oldYaml, BurpExtender.Yaml_Path);
                }
            } catch (IOException e) {
                throw new IllegalStateException(I18n.t("log.writeYamlFailed", BurpExtender.Yaml_Path), e);
            }
        }
    }

    /** 判断规则列表是否已包含业务字段完全相同的规则。 */
    public static boolean inYamlList(List<Map<String, Object>> rules, Map<String, Object> candidate) {
        for (Map<String, Object> rule : rules) {
            if (ifmapEqual(rule, candidate)) {
                return true;
            }
        }
        return false;
    }

    /** 比较两条规则的业务字段，忽略本地 ID、启用状态和分组。 */
    public static boolean ifmapEqual(Map<String, Object> first, Map<String, Object> second) {
        if (first == null || second == null) {
            return false;
        }
        Set<String> keys = new LinkedHashSet<String>();
        keys.addAll(first.keySet());
        keys.addAll(second.keySet());
        keys.remove("loaded");
        keys.remove("id");
        keys.remove("type");
        for (String key : keys) {
            if (!Objects.equals(first.get(key), second.get(key))) {
                return false;
            }
        }
        return true;
    }

    /** 实际读取实现；严格模式供写操作使用，禁止解析失败后继续覆盖原文件。 */
    private static Map<String, Object> readYamlInternal(String filePath, boolean strict) {
        Path path = Path.of(filePath).toAbsolutePath().normalize();
        if (!Files.exists(path)) {
            Map<String, Object> data = bundledYamlData();
            try {
                writeYamlInternal(data, filePath);
            } catch (IOException e) {
                BurpExtender.logStaticError(I18n.t("log.writeYamlFailed", filePath), e);
                if (strict) {
                    throw new YamlReadException(filePath, e);
                }
            }
            return data;
        }

        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            Object loaded = newSafeYaml().load(reader);
            return normalizeLoadedYaml(loaded);
        } catch (IOException | RuntimeException e) {
            BurpExtender.logStaticError(I18n.t("log.readYamlFailed", filePath), e);
            if (strict) {
                throw new YamlReadException(filePath, e);
            }
            return defaultYamlData();
        }
    }

    /** 从 JAR 内读取随版本发布的默认规则，资源缺失或损坏时才回退为空列表。 */
    private static Map<String, Object> bundledYamlData() {
        try (InputStream inputStream = YamlUtil.class.getResourceAsStream("/Rules.yaml")) {
            if (inputStream == null) {
                return defaultYamlData();
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream, StandardCharsets.UTF_8)
            )) {
                return normalizeLoadedYaml(newSafeYaml().load(reader));
            }
        } catch (IOException | RuntimeException e) {
            BurpExtender.logStaticError(I18n.t("log.readBundledYamlFailed"), e);
            return defaultYamlData();
        }
    }

    /** 校验 YAML 根结构、复制规则 Map，并确定性修复非法或重复 ID。 */
    private static Map<String, Object> normalizeLoadedYaml(Object loaded) {
        if (!(loaded instanceof Map<?, ?> loadedMap)) {
            throw new IllegalArgumentException("YAML root must be a map");
        }
        Object loadedRules = loadedMap.get("Load_List");
        if (!(loadedRules instanceof List<?> rawRules)) {
            throw new IllegalArgumentException("Load_List must be a list");
        }

        List<Map<String, Object>> rules = new ArrayList<Map<String, Object>>();
        for (Object rawRule : rawRules) {
            if (!(rawRule instanceof Map<?, ?> rawMap)) {
                throw new IllegalArgumentException("Every rule must be a map");
            }
            Map<String, Object> rule = new LinkedHashMap<String, Object>();
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (!(entry.getKey() instanceof String)) {
                    throw new IllegalArgumentException("Rule keys must be strings");
                }
                rule.put((String) entry.getKey(), entry.getValue());
            }
            rules.add(rule);
        }
        normalizeRuleIds(rules);

        Map<String, Object> data = defaultYamlData();
        data.put("Load_List", rules);
        return data;
    }

    /** 为非法和重复规则 ID 分配稳定的新 ID，避免 ID-only 操作误伤多条规则。 */
    private static void normalizeRuleIds(List<Map<String, Object>> rules) {
        Set<Integer> validIds = collectRuleIds(rules);
        int nextId = nextRuleId(validIds);
        Set<Integer> seenIds = new HashSet<Integer>();
        for (Map<String, Object> rule : rules) {
            Integer id = parsePositiveRuleId(rule.get("id"));
            if (id == null || !seenIds.add(id)) {
                while (validIds.contains(nextId)) {
                    nextId++;
                }
                rule.put("id", nextId);
                validIds.add(nextId);
                seenIds.add(nextId);
                nextId++;
            } else {
                rule.put("id", id);
            }
        }
    }

    /** 收集当前所有可用正整数 ID。 */
    private static Set<Integer> collectRuleIds(List<Map<String, Object>> rules) {
        Set<Integer> ids = new HashSet<Integer>();
        for (Map<String, Object> rule : rules) {
            if (rule != null) {
                Integer id = parsePositiveRuleId(rule.get("id"));
                if (id != null) {
                    ids.add(id);
                }
            }
        }
        return ids;
    }

    /** 解析合法的正整数规则 ID，超出 int 范围或格式错误时返回 null。 */
    private static Integer parsePositiveRuleId(Object value) {
        if (value == null) {
            return null;
        }
        try {
            int id = Integer.parseInt(value.toString().trim());
            return id > 0 ? id : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 计算下一个未使用的正整数 ID。 */
    private static int nextRuleId(Set<Integer> usedIds) {
        int nextId = 1;
        for (Integer id : usedIds) {
            if (id != null && id < Integer.MAX_VALUE) {
                nextId = Math.max(nextId, id + 1);
            }
        }
        while (usedIds.contains(nextId) && nextId < Integer.MAX_VALUE) {
            nextId++;
        }
        if (nextId <= 0 || usedIds.contains(nextId)) {
            throw new IllegalStateException("No available rule id");
        }
        return nextId;
    }

    /** 返回规则列表；内部标准化保证该字段始终存在且类型正确。 */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> ruleList(Map<String, Object> yamlData) {
        return (List<Map<String, Object>>) yamlData.get("Load_List");
    }

    /** 构造只允许标准 YAML 类型的解析器，拒绝自定义 Java 类型标签。 */
    private static Yaml newSafeYaml() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(false);
        return new Yaml(new SafeConstructor(loaderOptions));
    }

    /** 原子写入的内部实现，调用方必须持有 YAML_FILE_LOCK。 */
    private static void writeYamlInternal(Map<String, Object> data, String filePath) throws IOException {
        Map<String, Object> saveData = data == null
                ? defaultYamlData()
                : normalizeLoadedYaml(data);

        Path target = Path.of(filePath).toAbsolutePath().normalize();
        Path parent = target.getParent();
        Path fileName = target.getFileName();
        if (parent == null || fileName == null) {
            throw new IOException("YAML file path must point to a file");
        }
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, fileName.toString(), ".tmp");
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                new Yaml().dump(saveData, writer);
            }
            try {
                Files.move(
                        temporary,
                        target,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING
                );
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /** 统一记录写操作失败，调用方只得到 false，不会继续覆盖原文件。 */
    private static void logMutationFailure(String filePath, Throwable error) {
        String key = error instanceof YamlReadException ? "log.readYamlFailed" : "log.writeYamlFailed";
        BurpExtender.logStaticError(I18n.t(key, filePath), error);
    }

    /** 标记严格读取失败，供读改写流程立即终止。 */
    private static final class YamlReadException extends IllegalStateException {
        /** 保存读取失败的规则路径和原始异常。 */
        private YamlReadException(String filePath, Throwable cause) {
            super("Unable to read YAML file: " + filePath, cause);
        }
    }
}
