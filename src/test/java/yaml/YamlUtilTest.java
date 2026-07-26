package yaml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class YamlUtilTest {

    @TempDir
    Path temporaryDirectory;

    /** 重复或非法 ID 应在内存中被确定性修复，且不能改变已有唯一 ID。 */
    @Test
    void normalizesDuplicateAndInvalidRuleIds() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        Files.writeString(
                yamlFile,
                """
                Load_List:
                  - {id: 5, name: first}
                  - {id: 5, name: duplicate}
                  - {id: bad, name: invalid}
                  - {id: 9, name: last}
                """,
                StandardCharsets.UTF_8
        );

        List<Map<String, Object>> rules = rules(YamlUtil.readYaml(yamlFile.toString()));

        assertEquals(List.of(5, 10, 11, 9), rules.stream().map(rule -> rule.get("id")).toList());
    }

    /** 解析失败后的读改写操作必须中止，并逐字节保留用户原文件。 */
    @Test
    void malformedYamlIsNeverOverwrittenByMutation() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        String malformedYaml = "Load_List: [\n";
        Files.writeString(yamlFile, malformedYaml, StandardCharsets.UTF_8);

        Map<String, Object> update = new HashMap<String, Object>();
        update.put("id", 1);

        assertFalse(YamlUtil.updateYaml(update, yamlFile.toString()));
        assertEquals(malformedYaml, Files.readString(yamlFile, StandardCharsets.UTF_8));
    }

    /** 选中规范化后的重复规则时，只允许更新对应的一条记录。 */
    @Test
    void updatesOnlyTheSelectedNormalizedRule() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        Files.writeString(
                yamlFile,
                """
                Load_List:
                  - {id: 5, name: first}
                  - {id: 5, name: second}
                """,
                StandardCharsets.UTF_8
        );

        List<Map<String, Object>> normalizedRules = rules(YamlUtil.readYaml(yamlFile.toString()));
        Map<String, Object> selectedRule = new HashMap<String, Object>(normalizedRules.get(1));
        selectedRule.put("name", "updated");

        assertTrue(YamlUtil.updateYaml(selectedRule, yamlFile.toString()));
        List<Map<String, Object>> savedRules = rules(YamlUtil.readYaml(yamlFile.toString()));
        assertEquals(List.of("first", "updated"), savedRules.stream().map(rule -> rule.get("name")).toList());
        assertEquals(2, new HashSet<Object>(savedRules.stream().map(rule -> rule.get("id")).toList()).size());
    }

    /** 安全解析器必须拒绝 YAML 中的任意 Java 类型标签。 */
    @Test
    void rejectsCustomJavaTypeTags() {
        assertThrows(
                RuntimeException.class,
                () -> YamlUtil.readStrYaml("Load_List: [!!java.util.Date '2026-07-26']")
        );
    }

    /** 原子写入应固定使用 UTF-8，并生成可再次读取的 YAML。 */
    @Test
    void writesUtf8YamlThatCanBeReadAgain() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        Map<String, Object> rule = new HashMap<String, Object>();
        rule.put("id", 1);
        rule.put("name", "中文规则");
        Map<String, Object> yaml = YamlUtil.defaultYamlData();
        rules(yaml).add(rule);

        assertTrue(YamlUtil.writeYaml(yaml, yamlFile.toString()));
        assertTrue(Files.readString(yamlFile, StandardCharsets.UTF_8).contains("中文规则"));
        assertEquals("中文规则", rules(YamlUtil.readYaml(yamlFile.toString())).get(0).get("name"));
    }

    /** 首次启动应从 JAR 复制完整默认规则，而不是生成无法扫描的空列表。 */
    @Test
    void createsMissingRuleFileFromBundledDefaults() {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");

        List<Map<String, Object>> bundledRules = rules(YamlUtil.readYaml(yamlFile.toString()));

        assertTrue(Files.exists(yamlFile));
        assertFalse(bundledRules.isEmpty());
        assertEquals(bundledRules.size(), rules(YamlUtil.readYaml(yamlFile.toString())).size());
    }

    /** 规则组重命名必须一次更新全部匹配规则，其他分组保持不变。 */
    @Test
    void renamesRuleGroupAtomically() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        Files.writeString(
                yamlFile,
                """
                Load_List:
                  - {id: 1, type: old, name: first}
                  - {id: 2, type: other, name: second}
                  - {id: 3, type: old, name: third}
                """,
                StandardCharsets.UTF_8
        );

        assertTrue(YamlUtil.renameRuleGroup("old", "renamed", yamlFile.toString()));
        assertEquals(
                List.of("renamed", "other", "renamed"),
                rules(YamlUtil.readYaml(yamlFile.toString())).stream().map(rule -> rule.get("type")).toList()
        );
    }

    /** 规则组删除必须一次移除全部匹配规则，不能误删其他分组。 */
    @Test
    void removesRuleGroupAtomically() throws IOException {
        Path yamlFile = temporaryDirectory.resolve("Rules.yaml");
        Files.writeString(
                yamlFile,
                """
                Load_List:
                  - {id: 1, type: remove, name: first}
                  - {id: 2, type: keep, name: second}
                  - {id: 3, type: remove, name: third}
                """,
                StandardCharsets.UTF_8
        );

        assertTrue(YamlUtil.removeRuleGroup("remove", yamlFile.toString()));
        List<Map<String, Object>> savedRules = rules(YamlUtil.readYaml(yamlFile.toString()));
        assertEquals(1, savedRules.size());
        assertEquals("keep", savedRules.get(0).get("type"));
    }

    /** 测试辅助方法：取得标准化后的规则列表。 */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rules(Map<String, Object> yaml) {
        return (List<Map<String, Object>>) yaml.get("Load_List");
    }
}
