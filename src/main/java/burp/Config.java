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
    private JComboBox<LanguageOption> languageBox;
    private JLabel setupSummaryLabel;
    private JLabel progressSummaryLabel;
    private JLabel pathsProgressLabel;
    private JLabel workersProgressLabel;
    private JLabel resultProgressLabel;

    private JButton scanningButton;
    private JButton headersButton;
    private JCheckBox ruleEnabledCheck;
    private JLabel editorStateLabel;

    private JTextField ruleNameField;
    private JComboBox<String> ruleMethodBox;
    private JComboBox<String> ruleGroupBox;
    private JTextField ruleUrlField;
    private JTextArea ruleRegexArea;
    private JTextArea ruleInfoArea;
    private JTextField ruleStateField;

    private String editingRuleId;
    private boolean refreshingLanguage;

    public Config(BurpExtender burp) {
        this.burp = burp;
    }

    private String t(String key, Object... args) {
        return burp.t(key, args);
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
        JPanel panel = createSectionPanel("section.scanControl");
        panel.setLayout(new BorderLayout(12, 8));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));

        scanningButton = new JButton();
        applyToggleState(scanningButton, burp.on_off, "button.passiveScan");
        scanningButton.addActionListener(e -> {
            burp.on_off = !burp.on_off;
            applyToggleState(scanningButton, burp.on_off, "button.passiveScan");
            updateStatusLabel();
        });

        headersButton = new JButton();
        applyToggleState(headersButton, burp.Carry_head, "button.carryHeaders");
        headersButton.addActionListener(e -> {
            burp.Carry_head = !burp.Carry_head;
            applyToggleState(headersButton, burp.Carry_head, "button.carryHeaders");
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

        languageBox = new JComboBox<LanguageOption>();
        populateLanguageBox();
        languageBox.addActionListener(e -> {
            if (refreshingLanguage) {
                return;
            }
            Object selected = languageBox.getSelectedItem();
            if (selected instanceof LanguageOption) {
                burp.setLanguage(((LanguageOption) selected).code);
            }
        });

        controls.add(scanningButton);
        controls.add(headersButton);
        controls.add(localizedLabel("label.threads"));
        controls.add(spinner1);
        controls.add(localizedLabel("label.hostFilter"));
        controls.add(hostFilterField);
        controls.add(localizedLabel("label.language"));
        controls.add(languageBox);

        setupSummaryLabel = new JLabel();
        setupSummaryLabel.setForeground(new Color(80, 80, 80));

        panel.add(controls, BorderLayout.NORTH);
        panel.add(setupSummaryLabel, BorderLayout.SOUTH);
        updateStatusLabel();
        return panel;
    }

    private JPanel buildRuleSourcePanel() {
        JPanel panel = createSectionPanel("section.ruleSource");
        panel.setLayout(new BorderLayout(12, 8));

        txtfield1 = new JTextField(yaml_path);
        txtfield1.setEditable(false);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton updateButton = localizedButton("button.cloudDownloadRules");
        updateButton.addActionListener(e -> YamlUtil.init_Yaml(burp, one));
        JButton reloadButton = localizedButton("button.localReloadRules");
        reloadButton.addActionListener(e -> reloadRulesAndRestoreSelection(getCurrentGroupName(), editingRuleId));
        buttons.add(updateButton);
        buttons.add(reloadButton);

        panel.add(txtfield1, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildProgressPanel() {
        JPanel panel = createSectionPanel("section.progress");
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
        JButton cancelButton = localizedButton("button.cancelScans");
        cancelButton.addActionListener(e -> burp.cancelActiveScans());
        JButton resetButton = localizedButton("button.resetProgress");
        resetButton.addActionListener(e -> burp.resetScanProgressAndReloadRules());
        buttons.add(cancelButton);
        buttons.add(resetButton);

        panel.add(metrics, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        refreshProgressView();
        return panel;
    }

    private JPanel buildRuleBrowserPanel() {
        JPanel panel = createSectionPanel("section.ruleList");
        panel.setLayout(new BorderLayout(8, 8));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton newRuleButton = localizedButton("button.newRule");
        newRuleButton.addActionListener(e -> prepareNewRuleForGroup(getCurrentGroupName()));
        JButton newGroupButton = localizedButton("button.newGroup");
        newGroupButton.addActionListener(e -> createGroupDraft());
        JButton renameGroupButton = localizedButton("button.renameGroup");
        renameGroupButton.addActionListener(e -> renameCurrentGroup());
        JButton deleteGroupButton = localizedButton("button.deleteGroup");
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
        JPanel panel = createSectionPanel("section.ruleEditor");
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
        ruleEnabledCheck = new JCheckBox(t("checkbox.enableRule"));
        ruleEnabledCheck.putClientProperty("i18n.textKey", "checkbox.enableRule");
        ruleEnabledCheck.setSelected(true);

        addFormRow(form, gbc, "form.ruleName", ruleNameField);
        addFormRow(form, gbc, "form.method", ruleMethodBox);
        addFormRow(form, gbc, "form.group", ruleGroupBox);
        addFormRow(form, gbc, "form.pathSuffix", ruleUrlField);
        addFormRow(form, gbc, "form.responseRegex", new JScrollPane(ruleRegexArea));
        addFormRow(form, gbc, "form.info", new JScrollPane(ruleInfoArea));
        addFormRow(form, gbc, "form.statusCodes", ruleStateField);

        gbc.gridx = 1;
        gbc.weightx = 1;
        form.add(ruleEnabledCheck, gbc);
        gbc.gridy++;

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton saveButton = localizedButton("button.saveRule");
        saveButton.addActionListener(e -> saveRuleFromEditor());
        JButton clearButton = localizedButton("button.clearEditor");
        clearButton.addActionListener(e -> prepareNewRuleForGroup(getSelectedEditorGroup()));
        JButton deleteButton = localizedButton("button.deleteRule");
        deleteButton.addActionListener(e -> deleteCurrentRule());
        buttonRow.add(saveButton);
        buttonRow.add(clearButton);
        buttonRow.add(deleteButton);

        editorStateLabel = new JLabel(t("editor.selectOrNew"));
        editorStateLabel.setForeground(new Color(80, 80, 80));

        panel.add(form, BorderLayout.CENTER);
        panel.add(buttonRow, BorderLayout.NORTH);
        panel.add(editorStateLabel, BorderLayout.SOUTH);
        refreshGroupChoices();
        prepareNewRuleForGroup(null);
        return panel;
    }

    private JPanel createSectionPanel(String titleKey) {
        JPanel panel = new JPanel();
        panel.putClientProperty("i18n.titleKey", titleKey);
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                t(titleKey),
                TitledBorder.LEADING,
                TitledBorder.TOP
        ));
        return panel;
    }

    private JLabel localizedLabel(String key) {
        JLabel label = new JLabel(t(key));
        label.putClientProperty("i18n.textKey", key);
        return label;
    }

    private JButton localizedButton(String key) {
        JButton button = new JButton(t(key));
        button.putClientProperty("i18n.textKey", key);
        return button;
    }

    private void addFormRow(JPanel panel, GridBagConstraints gbc, String labelKey, Component component) {
        gbc.gridx = 0;
        gbc.weightx = 0;
        panel.add(localizedLabel(labelKey), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        panel.add(component, gbc);
        gbc.gridy++;
    }

    private void applyToggleState(JButton button, boolean enabled, String labelKey) {
        button.putClientProperty("i18n.toggleKey", labelKey);
        button.setText(t("toggle.state", t(labelKey), t(enabled ? "state.on" : "state.off")));
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
                t("label.currentConfig")
                        + (burp.on_off ? t("label.passiveOn") : t("label.passiveOff"))
                        + " | " + t("label.threads") + " " + burp.getConfiguredThreadCount()
                        + " | " + t("label.headers") + " " + (burp.Carry_head ? t("state.on") : t("state.off"))
                        + " | " + t("label.filter") + " " + hostFilterField.getText().trim()
        );
    }

    public void refreshProgressView() {
        if (progressSummaryLabel == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            progressSummaryLabel.setText(t("progress.summary", burp.getActiveScanCount(), burp.getScanGeneration()));
            pathsProgressLabel.setText(t("progress.paths", burp.getPathsQueuedCount(), burp.getPathsCompletedCount(), burp.getSkippedPathCount()));
            workersProgressLabel.setText(t("progress.workers", burp.getRunningTaskCount(), burp.getFinishedTaskCount()));
            resultProgressLabel.setText(t("progress.results", burp.getMatchCount(), burp.getTimeoutCount()));
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

    public void reloadRulesFromDisk() {
        reloadRulesAndRestoreSelection(getCurrentGroupName(), editingRuleId);
    }

    public void refreshLanguage() {
        if (one == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            refreshingLanguage = true;
            try {
                refreshComponentText(one);
                applyToggleState(scanningButton, burp.on_off, "button.passiveScan");
                applyToggleState(headersButton, burp.Carry_head, "button.carryHeaders");
                populateLanguageBox();
                updateStatusLabel();
                refreshProgressView();
                if (burp.views != null) {
                    for (View view : burp.views.values()) {
                        view.refreshLanguage();
                    }
                }
                handleGroupSelectionChanged();
            } finally {
                refreshingLanguage = false;
            }
        });
    }

    private void refreshComponentText(Component component) {
        if (component instanceof JComponent) {
            JComponent jComponent = (JComponent) component;
            Object textKey = jComponent.getClientProperty("i18n.textKey");
            if (textKey != null) {
                if (component instanceof AbstractButton) {
                    ((AbstractButton) component).setText(t(textKey.toString()));
                } else if (component instanceof JLabel) {
                    ((JLabel) component).setText(t(textKey.toString()));
                }
            }
            Object titleKey = jComponent.getClientProperty("i18n.titleKey");
            if (titleKey != null && jComponent.getBorder() instanceof TitledBorder) {
                ((TitledBorder) jComponent.getBorder()).setTitle(t(titleKey.toString()));
                jComponent.repaint();
            }
        }
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                refreshComponentText(child);
            }
        }
    }

    private void populateLanguageBox() {
        if (languageBox == null) {
            return;
        }
        String current = burp.getLanguage();
        languageBox.removeAllItems();
        languageBox.addItem(new LanguageOption(I18n.DEFAULT_LANGUAGE, t("language.zh")));
        languageBox.addItem(new LanguageOption(I18n.ENGLISH_LANGUAGE, t("language.en")));
        for (int i = 0; i < languageBox.getItemCount(); i++) {
            if (languageBox.getItemAt(i).code.equals(current)) {
                languageBox.setSelectedIndex(i);
                break;
            }
        }
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
        editorStateLabel.setText(t("editor.editing", entry.id, entry.type));
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
        String selectedGroup = getSelectedEditorGroup();
        editorStateLabel.setText(selectedGroup == null ? t("editor.newNoGroup") : t("editor.newWithGroup", selectedGroup));
    }

    private void saveRuleFromEditor() {
        String group = getSelectedEditorGroup();
        if (group == null || group.trim().isEmpty()) {
            burp.prompt(one, t("prompt.groupRequired"));
            return;
        }
        String name = ruleNameField.getText().trim();
        String url = ruleUrlField.getText().trim();
        String regex = ruleRegexArea.getText().trim();
        String info = ruleInfoArea.getText().trim();
        String state = ruleStateField.getText().trim();
        if (name.isEmpty() || url.isEmpty() || regex.isEmpty() || state.isEmpty()) {
            burp.prompt(one, t("prompt.ruleRequired"));
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
            editorStateLabel.setText(t("editor.created", editingRuleId));
        } else {
            YamlUtil.updateYaml(saveMap, yaml_path);
            editorStateLabel.setText(t("editor.saved", editingRuleId));
        }

        reloadRulesAndRestoreSelection(group, editingRuleId);
    }

    private void deleteCurrentRule() {
        if (editingRuleId == null) {
            burp.prompt(one, t("prompt.selectRuleFirst"));
            return;
        }
        int result = JOptionPane.showConfirmDialog(one, t("confirm.deleteRule"), t("dialog.deleteRule"), JOptionPane.YES_NO_OPTION);
        if (result != JOptionPane.YES_OPTION) {
            return;
        }
        String group = getCurrentGroupName();
        YamlUtil.removeYaml(editingRuleId, yaml_path);
        prepareNewRuleForGroup(group);
        reloadRulesAndRestoreSelection(group, null);
    }

    private void createGroupDraft() {
        String name = JOptionPane.showInputDialog(one, t("dialog.newGroup"), getCurrentGroupName() == null ? "default" : getCurrentGroupName());
        if (name == null || name.trim().isEmpty()) {
            return;
        }
        String normalized = name.trim();
        refreshGroupChoices();
        ruleGroupBox.setSelectedItem(normalized);
        prepareNewRuleForGroup(normalized);
        editorStateLabel.setText(t("editor.groupDraft", normalized));
    }

    private void renameCurrentGroup() {
        String current = getCurrentGroupName();
        if (current == null) {
            burp.prompt(one, t("prompt.noGroupToRename"));
            return;
        }
        String renamed = JOptionPane.showInputDialog(one, t("dialog.renameGroup"), current);
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
            burp.prompt(one, t("prompt.noGroupToDelete"));
            return;
        }
        int result = JOptionPane.showConfirmDialog(one, t("confirm.deleteGroup", current), t("dialog.deleteGroup"), JOptionPane.YES_NO_OPTION);
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

    private static class LanguageOption {
        private final String code;
        private final String label;

        private LanguageOption(String code, String label) {
            this.code = code;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
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
