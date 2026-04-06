package burp;

import yaml.YamlUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Config {
    private JPanel one;
    private JTextField txtfield1;
    public String yaml_path = BurpExtender.Yaml_Path;
    public JSpinner spinner1;
    private final BurpExtender burp;
    public JTabbedPane ruleTabbedPane;

    private JTextField hostFilterField;
    private JLabel setupSummaryLabel;
    private JLabel progressSummaryLabel;
    private JLabel pathsProgressLabel;
    private JLabel workersProgressLabel;
    private JLabel resultProgressLabel;

    private JTextField ruleNameField;
    private JComboBox<String> ruleMethodBox;
    private JComboBox<String> ruleGroupBox;
    private JTextField ruleUrlField;
    private JTextArea ruleRegexArea;
    private JTextArea ruleInfoArea;
    private JTextField ruleStateField;
    private JCheckBox ruleEnabledCheck;
    private JLabel editorStateLabel;

    private String editingRuleId;

    public Config(BurpExtender burp) {
        this.burp = burp;
    }

    private void $$$setupUI$$$() {
        if (one != null) {
            return;
        }

        one = new JPanel(new BorderLayout(12, 12));
        one.setBorder(new EmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(buildScanControlPanel());
        top.add(Box.createVerticalStrut(10));
        top.add(buildRuleSourcePanel());
        top.add(Box.createVerticalStrut(10));
        top.add(buildProgressPanel());

        JSplitPane contentSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        contentSplit.setResizeWeight(0.56);
        contentSplit.setBorder(null);
        contentSplit.setLeftComponent(buildRuleBrowserPanel());
        contentSplit.setRightComponent(buildRuleEditorPanel());

        one.add(top, BorderLayout.NORTH);
        one.add(contentSplit, BorderLayout.CENTER);
    }

    private JPanel buildScanControlPanel() {
        JPanel panel = createSectionPanel("扫描控制");
        panel.setLayout(new BorderLayout(12, 8));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        JButton scanningButton = new JButton();
        applyToggleState(scanningButton, burp.on_off, "被动扫描");
        scanningButton.addActionListener(e -> {
            burp.on_off = !burp.on_off;
            applyToggleState(scanningButton, burp.on_off, "被动扫描");
            updateStatusLabel();
        });

        JButton headersButton = new JButton();
        applyToggleState(headersButton, burp.Carry_head, "携带请求头");
        headersButton.addActionListener(e -> {
            burp.Carry_head = !burp.Carry_head;
            applyToggleState(headersButton, burp.Carry_head, "携带请求头");
            updateStatusLabel();
        });

        JButton domainButton = new JButton();
        applyToggleState(domainButton, burp.DomainScan, "域名扫描");
        domainButton.addActionListener(e -> {
            burp.DomainScan = !burp.DomainScan;
            applyToggleState(domainButton, burp.DomainScan, "域名扫描");
            updateStatusLabel();
        });

        JButton bypassButton = new JButton();
        applyToggleState(bypassButton, burp.Bypass, "绕过扫描");
        bypassButton.addActionListener(e -> {
            burp.Bypass = !burp.Bypass;
            applyToggleState(bypassButton, burp.Bypass, "绕过扫描");
            updateStatusLabel();
        });

        SpinnerNumberModel model = new SpinnerNumberModel(10, 1, 500, 1);
        spinner1 = new JSpinner(model);
        ((JSpinner.DefaultEditor) spinner1.getEditor()).getTextField().setColumns(4);
        spinner1.addChangeListener(e -> {
            burp.resetThreadPool();
            updateStatusLabel();
        });

        hostFilterField = new JTextField("*", 28);
        hostFilterField.getDocument().addDocumentListener(SimpleDocumentListener.onChange(this::syncHostFilter));
        burp.Host_txtfield = hostFilterField;

        controls.add(scanningButton);
        controls.add(headersButton);
        controls.add(domainButton);
        controls.add(bypassButton);
        controls.add(new JLabel("线程数"));
        controls.add(spinner1);
        controls.add(new JLabel("主机过滤"));
        controls.add(hostFilterField);

        setupSummaryLabel = new JLabel();
        setupSummaryLabel.setForeground(new Color(80, 80, 80));

        panel.add(controls, BorderLayout.NORTH);
        panel.add(setupSummaryLabel, BorderLayout.SOUTH);
        updateStatusLabel();
        return panel;
    }

    private JPanel buildRuleSourcePanel() {
        JPanel panel = createSectionPanel("规则来源");
        panel.setLayout(new BorderLayout(12, 8));

        txtfield1 = new JTextField(yaml_path);
        txtfield1.setEditable(false);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton updateButton = new JButton("更新规则");
        updateButton.addActionListener(e -> YamlUtil.init_Yaml(burp, one));
        JButton reloadButton = new JButton("重新加载规则");
        reloadButton.addActionListener(e -> reloadRulesAndRestoreSelection(getCurrentGroupName(), editingRuleId));
        buttons.add(updateButton);
        buttons.add(reloadButton);

        panel.add(txtfield1, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildProgressPanel() {
        JPanel panel = createSectionPanel("扫描进度");
        panel.setLayout(new BorderLayout(12, 8));

        JPanel metrics = new JPanel(new GridLayout(0, 1, 0, 4));
        progressSummaryLabel = new JLabel();
        pathsProgressLabel = new JLabel();
        workersProgressLabel = new JLabel();
        resultProgressLabel = new JLabel();
        metrics.add(progressSummaryLabel);
        metrics.add(pathsProgressLabel);
        metrics.add(workersProgressLabel);
        metrics.add(resultProgressLabel);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton cancelButton = new JButton("取消运行中扫描");
        cancelButton.addActionListener(e -> burp.cancelActiveScans());
        JButton resetButton = new JButton("重置进度");
        resetButton.addActionListener(e -> burp.resetScanMetrics());
        buttons.add(cancelButton);
        buttons.add(resetButton);

        panel.add(metrics, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        refreshProgressView();
        return panel;
    }

    private JPanel buildRuleBrowserPanel() {
        JPanel panel = createSectionPanel("规则列表");
        panel.setLayout(new BorderLayout(8, 8));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton newRuleButton = new JButton("新建规则");
        newRuleButton.addActionListener(e -> prepareNewRuleForGroup(getCurrentGroupName()));
        JButton newGroupButton = new JButton("新建规则组");
        newGroupButton.addActionListener(e -> createGroupDraft());
        JButton renameGroupButton = new JButton("重命名规则组");
        renameGroupButton.addActionListener(e -> renameCurrentGroup());
        JButton deleteGroupButton = new JButton("删除规则组");
        deleteGroupButton.addActionListener(e -> deleteCurrentGroup());
        toolbar.add(newRuleButton);
        toolbar.add(newGroupButton);
        toolbar.add(renameGroupButton);
        toolbar.add(deleteGroupButton);

        ruleTabbedPane = new JTabbedPane();
        ruleTabbedPane.addChangeListener(e -> handleGroupSelectionChanged());
        Bfunc.show_yaml(burp);

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(ruleTabbedPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildRuleEditorPanel() {
        JPanel panel = createSectionPanel("规则编辑器");
        panel.setLayout(new BorderLayout(8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0;

        ruleNameField = new JTextField();
        ruleMethodBox = new JComboBox<>(new String[]{"GET", "POST"});
        ruleGroupBox = new JComboBox<>();
        ruleGroupBox.setEditable(true);
        ruleUrlField = new JTextField();
        ruleRegexArea = new JTextArea(6, 24);
        ruleRegexArea.setLineWrap(true);
        ruleRegexArea.setWrapStyleWord(true);
        ruleInfoArea = new JTextArea(4, 24);
        ruleInfoArea.setLineWrap(true);
        ruleInfoArea.setWrapStyleWord(true);
        ruleStateField = new JTextField("200");
        ruleEnabledCheck = new JCheckBox("启用规则");
        ruleEnabledCheck.setSelected(true);

        addFormRow(form, gbc, "规则名称", ruleNameField);
        addFormRow(form, gbc, "请求方法", ruleMethodBox);
        addFormRow(form, gbc, "规则组", ruleGroupBox);
        addFormRow(form, gbc, "路径后缀", ruleUrlField);
        addFormRow(form, gbc, "响应正则", new JScrollPane(ruleRegexArea));
        addFormRow(form, gbc, "说明 / 备注", new JScrollPane(ruleInfoArea));
        addFormRow(form, gbc, "匹配状态码", ruleStateField);

        gbc.gridx = 1;
        gbc.weightx = 1;
        form.add(ruleEnabledCheck, gbc);
        gbc.gridy++;

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton saveButton = new JButton("保存规则");
        saveButton.addActionListener(e -> saveRuleFromEditor());
        JButton clearButton = new JButton("清空编辑器");
        clearButton.addActionListener(e -> prepareNewRuleForGroup(getSelectedEditorGroup()));
        JButton deleteButton = new JButton("删除规则");
        deleteButton.addActionListener(e -> deleteCurrentRule());
        buttonRow.add(saveButton);
        buttonRow.add(clearButton);
        buttonRow.add(deleteButton);

        editorStateLabel = new JLabel("请从左侧选择规则，或新建一条规则。");
        editorStateLabel.setForeground(new Color(80, 80, 80));

        panel.add(form, BorderLayout.CENTER);
        panel.add(buttonRow, BorderLayout.NORTH);
        panel.add(editorStateLabel, BorderLayout.SOUTH);
        refreshGroupChoices();
        prepareNewRuleForGroup(null);
        return panel;
    }

    private JPanel createSectionPanel(String title) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                title,
                TitledBorder.LEADING,
                TitledBorder.TOP
        ));
        return panel;
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, String label, Component component) {
        gbc.gridx = 0;
        gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        panel.add(component, gbc);
        gbc.gridy++;
    }

    private void applyToggleState(JButton button, boolean enabled, String label) {
        button.setText(label + "：" + (enabled ? "开启" : "关闭"));
        button.setBackground(enabled ? Color.green : UIManager.getColor("Button.background"));
    }

    private void syncHostFilter() {
        if (burp.Host_txtfield != hostFilterField) {
            burp.Host_txtfield = hostFilterField;
        }
        updateStatusLabel();
    }

    private void updateStatusLabel() {
        if (setupSummaryLabel == null) {
            return;
        }
        setupSummaryLabel.setText(
                "当前配置："
                        + (burp.on_off ? "被动扫描已开启" : "被动扫描已关闭")
                        + " | 线程数 " + burp.getConfiguredThreadCount()
                        + " | 请求头 " + (burp.Carry_head ? "开启" : "关闭")
                        + " | 域名扫描 " + (burp.DomainScan ? "开启" : "关闭")
                        + " | 绕过扫描 " + (burp.Bypass ? "开启" : "关闭")
                        + " | 过滤器 " + hostFilterField.getText().trim()
        );
    }

    public void refreshProgressView() {
        if (progressSummaryLabel == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            progressSummaryLabel.setText(
                    "活动扫描数 " + burp.getActiveScanCount()
                            + " | 代次 " + burp.getScanGeneration()
            );
            pathsProgressLabel.setText(
                    "已排队路径 " + burp.getPathsQueuedCount()
                            + " | 已完成路径 " + burp.getPathsCompletedCount()
                            + " | 已跳过 " + burp.getSkippedPathCount()
            );
            workersProgressLabel.setText(
                    "运行中任务 " + burp.getRunningTaskCount()
                            + " | 已完成任务 " + burp.getFinishedTaskCount()
            );
            resultProgressLabel.setText(
                    "命中结果 " + burp.getMatchCount()
                            + " | 超时次数 " + burp.getTimeoutCount()
            );
        });
    }

    public void onRuleSelected(View.LogEntry logEntry) {
        if (logEntry == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> loadRuleIntoEditor(logEntry));
    }

    public void afterRulesReload() {
        refreshGroupChoices();
        handleGroupSelectionChanged();
    }

    private void handleGroupSelectionChanged() {
        if (ruleNameField == null || ruleGroupBox == null) {
            return;
        }
        String group = getCurrentGroupName();
        if (group != null && ruleGroupBox != null) {
            ruleGroupBox.setSelectedItem(group);
        }
        View view = group == null ? null : burp.views.get(group);
        if (view != null && view.Choice != null) {
            loadRuleIntoEditor(view.Choice);
        } else {
            prepareNewRuleForGroup(group);
        }
    }

    private void loadRuleIntoEditor(View.LogEntry entry) {
        editingRuleId = entry.id;
        ruleNameField.setText(entry.name);
        ruleMethodBox.setSelectedItem(entry.method);
        ruleGroupBox.setSelectedItem(entry.type);
        ruleUrlField.setText(entry.url);
        ruleRegexArea.setText(entry.re);
        ruleInfoArea.setText(entry.info);
        ruleStateField.setText(entry.state);
        ruleEnabledCheck.setSelected(entry.loaded);
        editorStateLabel.setText("正在编辑规则 #" + entry.id + "，所属规则组“" + entry.type + "”。");
    }

    private void prepareNewRuleForGroup(String groupName) {
        editingRuleId = null;
        ruleNameField.setText("");
        ruleMethodBox.setSelectedItem("GET");
        ruleUrlField.setText("");
        ruleRegexArea.setText("");
        ruleInfoArea.setText("");
        ruleStateField.setText("200");
        ruleEnabledCheck.setSelected(true);
        if (groupName != null && !groupName.trim().isEmpty()) {
            ruleGroupBox.setSelectedItem(groupName);
        } else if (ruleGroupBox.getItemCount() > 0) {
            ruleGroupBox.setSelectedIndex(0);
        } else {
            ruleGroupBox.getEditor().setItem("default");
        }
        editorStateLabel.setText("正在新建规则" + (getSelectedEditorGroup() == null ? "。" : "，所属规则组“" + getSelectedEditorGroup() + "”。"));
    }

    private void saveRuleFromEditor() {
        String group = getSelectedEditorGroup();
        if (group == null || group.trim().isEmpty()) {
            burp.prompt(one, "规则组不能为空。");
            return;
        }
        String name = ruleNameField.getText().trim();
        String url = ruleUrlField.getText().trim();
        String regex = ruleRegexArea.getText().trim();
        String info = ruleInfoArea.getText().trim();
        String state = ruleStateField.getText().trim();
        if (name.isEmpty() || url.isEmpty() || regex.isEmpty() || state.isEmpty()) {
            burp.prompt(one, "规则名称、路径后缀、响应正则和匹配状态码不能为空。");
            return;
        }

        Map<String, Object> yaml = YamlUtil.readYaml(yaml_path);
        List<Map<String, Object>> ruleList = (List<Map<String, Object>>) yaml.get("Load_List");
        int nextId = 1;
        for (Map<String, Object> zidian : ruleList) {
            nextId = Math.max(nextId, Integer.parseInt(zidian.get("id").toString()) + 1);
        }

        java.util.HashMap<String, Object> saveMap = new java.util.HashMap<String, Object>();
        saveMap.put("type", group);
        saveMap.put("id", editingRuleId == null ? nextId : Integer.parseInt(editingRuleId));
        saveMap.put("loaded", ruleEnabledCheck.isSelected());
        saveMap.put("name", name);
        saveMap.put("method", String.valueOf(ruleMethodBox.getSelectedItem()));
        saveMap.put("url", url);
        saveMap.put("re", regex);
        saveMap.put("info", info);
        saveMap.put("state", state);

        if (editingRuleId == null) {
            YamlUtil.addYaml(saveMap, yaml_path);
            editingRuleId = String.valueOf(saveMap.get("id"));
            editorStateLabel.setText("已创建规则 #" + editingRuleId + "。");
        } else {
            YamlUtil.updateYaml(saveMap, yaml_path);
            editorStateLabel.setText("已保存规则 #" + editingRuleId + "。");
        }

        reloadRulesAndRestoreSelection(group, editingRuleId);
    }

    private void deleteCurrentRule() {
        if (editingRuleId == null) {
            burp.prompt(one, "请先选择一条规则。");
            return;
        }
        int result = JOptionPane.showConfirmDialog(one, "确认删除当前选中的规则吗？", "删除规则", JOptionPane.YES_NO_OPTION);
        if (result != JOptionPane.YES_OPTION) {
            return;
        }
        String group = getCurrentGroupName();
        YamlUtil.removeYaml(editingRuleId, yaml_path);
        prepareNewRuleForGroup(group);
        reloadRulesAndRestoreSelection(group, null);
    }

    private void createGroupDraft() {
        String name = JOptionPane.showInputDialog(one, "请输入新的规则组名称", getCurrentGroupName() == null ? "default" : getCurrentGroupName());
        if (name == null || name.trim().isEmpty()) {
            return;
        }
        String normalized = name.trim();
        refreshGroupChoices();
        ruleGroupBox.setSelectedItem(normalized);
        prepareNewRuleForGroup(normalized);
        editorStateLabel.setText("规则组草稿“" + normalized + "”已创建，请保存一条规则以正式写入。");
    }

    private void renameCurrentGroup() {
        String current = getCurrentGroupName();
        if (current == null) {
            burp.prompt(one, "当前没有可重命名的规则组。");
            return;
        }
        String renamed = JOptionPane.showInputDialog(one, "请输入新的规则组名称", current);
        if (renamed == null || renamed.trim().isEmpty() || renamed.trim().equals(current)) {
            return;
        }

        View view = burp.views.get(current);
        if (view == null) {
            return;
        }

        for (View.LogEntry logEntry : view.log) {
            java.util.Hashtable<String, Object> updateMap = new java.util.Hashtable<String, Object>();
            updateMap.put("id", Integer.parseInt(logEntry.id));
            updateMap.put("type", renamed.trim());
            updateMap.put("loaded", logEntry.loaded);
            updateMap.put("name", logEntry.name);
            updateMap.put("method", logEntry.method);
            updateMap.put("url", logEntry.url);
            updateMap.put("re", logEntry.re);
            updateMap.put("info", logEntry.info);
            updateMap.put("state", logEntry.state);
            YamlUtil.updateYaml(updateMap, yaml_path);
        }

        reloadRulesAndRestoreSelection(renamed.trim(), editingRuleId);
    }

    private void deleteCurrentGroup() {
        String current = getCurrentGroupName();
        if (current == null) {
            burp.prompt(one, "当前没有可删除的规则组。");
            return;
        }
        int result = JOptionPane.showConfirmDialog(one, "确认删除整个规则组“" + current + "”吗？", "删除规则组", JOptionPane.YES_NO_OPTION);
        if (result != JOptionPane.YES_OPTION) {
            return;
        }

        View view = burp.views.get(current);
        if (view != null) {
            for (View.LogEntry logEntry : new ArrayList<View.LogEntry>(view.log)) {
                YamlUtil.removeYaml(logEntry.id, yaml_path);
            }
        }
        editingRuleId = null;
        reloadRulesAndRestoreSelection(null, null);
    }

    public void refreshGroupChoices() {
        if (ruleGroupBox == null) {
            return;
        }
        Object selected = ruleGroupBox.getEditor().getItem();
        ruleGroupBox.removeAllItems();
        if (burp.views != null) {
            for (String key : burp.views.keySet()) {
                ruleGroupBox.addItem(key);
            }
        }
        if (selected != null && !selected.toString().trim().isEmpty()) {
            ruleGroupBox.setSelectedItem(selected.toString());
        }
    }

    private void reloadRulesAndRestoreSelection(String group, String ruleId) {
        Bfunc.show_yaml(burp);
        refreshGroupChoices();

        if (group != null) {
            for (int i = 0; i < ruleTabbedPane.getTabCount(); i++) {
                if (group.equals(ruleTabbedPane.getTitleAt(i))) {
                    ruleTabbedPane.setSelectedIndex(i);
                    break;
                }
            }
        }

        if (group != null && ruleId != null && burp.views != null && burp.views.containsKey(group)) {
            for (View.LogEntry entry : burp.views.get(group).log) {
                if (ruleId.equals(entry.id)) {
                    loadRuleIntoEditor(entry);
                    return;
                }
            }
        }

        handleGroupSelectionChanged();
    }

    private String getSelectedEditorGroup() {
        Object selected = ruleGroupBox.getEditor().getItem();
        if (selected == null) {
            return null;
        }
        String text = selected.toString().trim();
        return text.isEmpty() ? null : text;
    }

    private String getCurrentGroupName() {
        if (ruleTabbedPane == null || ruleTabbedPane.getTabCount() == 0 || ruleTabbedPane.getSelectedIndex() < 0) {
            return null;
        }
        return ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
    }

    public JComponent $$$getRootComponent$$$() {
        $$$setupUI$$$();
        return one;
    }
}

class SimpleDocumentListener implements DocumentListener {
    private final Runnable onChange;

    private SimpleDocumentListener(Runnable onChange) {
        this.onChange = onChange;
    }

    public static SimpleDocumentListener onChange(Runnable onChange) {
        return new SimpleDocumentListener(onChange);
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        onChange.run();
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        onChange.run();
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        onChange.run();
    }
}
