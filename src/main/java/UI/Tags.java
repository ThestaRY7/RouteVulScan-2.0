package UI;

import burp.BurpExtender;
import burp.Config;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Tags extends AbstractTableModel {
    public final BurpExtender burp;
    public final Config config;

    private JSplitPane top;
    private JSplitPane splitPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane tabs;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;
    private JPopupMenu m_popupMenu;
    private JMenuItem delMenItem;
    private JMenuItem delAllMenItem;
    private JLabel statusLabel;
    private JCheckBox enableFilterCheckBox;
    private JLabel thresholdLabel;
    private JSpinner thresholdSpinner;
    private JButton refreshButton;
    private JButton clearButton;
    public URLTable Utable;
    private JScrollPane UscrollPane;
    public List<TablesData> Udatas = new ArrayList<TablesData>();
    public HttpRequestEditor HRequestTextEditor;
    public HttpResponseEditor HResponseTextEditor;
    private HttpRequestResponse currentlyDisplayedItem;
    private final List<LogEntry> logEntries = new ArrayList<LogEntry>();
    private int nextEntryId;

    public Tags(BurpExtender burp, Config config) {
        this.burp = burp;
        this.config = config;
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                buildUi();
            } else {
                SwingUtilities.invokeAndWait(this::buildUi);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize RouteVulScan UI", e);
        }
    }

    private String t(String key, Object... args) {
        return burp.t(key, args);
    }

    private void buildUi() {
        try {
            this.top = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            tabs = new JTabbedPane();
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            enableFilterCheckBox = new JCheckBox(t("checkbox.duplicateFilter"));
            enableFilterCheckBox.setSelected(false);
            enableFilterCheckBox.setToolTipText(t("tooltip.duplicateFilter"));
            enableFilterCheckBox.addActionListener(e -> refreshTable());

            thresholdLabel = new JLabel(t("label.duplicateThreshold"));
            thresholdSpinner = new JSpinner(new SpinnerNumberModel(5, 2, 100, 1));
            thresholdSpinner.addChangeListener(e -> refreshTable());

            filterPanel.add(enableFilterCheckBox);
            filterPanel.add(thresholdLabel);
            filterPanel.add(thresholdSpinner);

            refreshButton = new JButton(t("button.refreshView"));
            refreshButton.addActionListener(e -> refreshTable());
            filterPanel.add(refreshButton);

            clearButton = new JButton(t("button.clearHistory"));
            clearButton.addActionListener(e -> clearHistory());
            filterPanel.add(clearButton);

            statusLabel = new JLabel(t("status.records", 0, 0));
            filterPanel.add(statusLabel);

            Utable = new URLTable(this);
            UscrollPane = new JScrollPane(Utable);

            m_popupMenu = new JPopupMenu();
            delMenItem = new JMenuItem(t("menu.deleteSelected"));
            delMenItem.addActionListener(new Remove_action(this));
            delAllMenItem = new JMenuItem(t("menu.clearAllHistory"));
            delAllMenItem.addActionListener(new Remove_All(this));
            m_popupMenu.add(delMenItem);
            m_popupMenu.add(delAllMenItem);
            Utable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent evt) {
                    jTable1MouseClicked(evt);
                }
            });

            JPanel tablePanel = new JPanel(new BorderLayout());
            tablePanel.add(filterPanel, BorderLayout.NORTH);
            tablePanel.add(UscrollPane, BorderLayout.CENTER);

            HjSplitPane = new JSplitPane();
            HjSplitPane.setResizeWeight(0.5D);
            HjSplitPane.setDividerSize(3);

            Ltable = new JTabbedPane();
            Rtable = new JTabbedPane();
            HRequestTextEditor = burp.api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            HResponseTextEditor = burp.api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
            Ltable.addTab(t("tab.request"), HRequestTextEditor.uiComponent());
            Rtable.addTab(t("tab.response"), HResponseTextEditor.uiComponent());
            HjSplitPane.add(Ltable, "left");
            HjSplitPane.add(Rtable, "right");

            splitPane.add(tablePanel, "left");
            splitPane.add(HjSplitPane, "right");
            tabs.addTab(t("tab.results"), splitPane);
            tabs.addTab(t("tab.config"), config.$$$getRootComponent$$$());
            top.setTopComponent(tabs);
            burp.api.userInterface().applyThemeToComponent(top);
        } catch (Throwable t) {
            BurpExtender.logStaticError(burp.t("log.initResultsFailed"), t);
        }
    }

    public Component getUiComponent() {
        return this.top;
    }

    public void refreshLanguage() {
        if (top == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            enableFilterCheckBox.setText(t("checkbox.duplicateFilter"));
            enableFilterCheckBox.setToolTipText(t("tooltip.duplicateFilter"));
            thresholdLabel.setText(t("label.duplicateThreshold"));
            refreshButton.setText(t("button.refreshView"));
            clearButton.setText(t("button.clearHistory"));
            delMenItem.setText(t("menu.deleteSelected"));
            delAllMenItem.setText(t("menu.clearAllHistory"));
            Ltable.setTitleAt(0, t("tab.request"));
            Rtable.setTitleAt(0, t("tab.response"));
            tabs.setTitleAt(0, t("tab.results"));
            tabs.setTitleAt(1, t("tab.config"));
            fireTableStructureChanged();
            refreshTable();
        });
    }

    public void addLogEntry(String name, String method, String url, String state, String info, String length, HttpRequestResponse requestResponse) {
        long now = System.currentTimeMillis();
        addLogEntry(name, method, url, state, info, length, requestResponse, now, now);
    }

    /**
     * 保存一条完整结果。时间在首次写入时固化，后续过滤或刷新只重建视图，不重新生成业务数据。
     */
    public void addLogEntry(
            String name,
            String method,
            String url,
            String state,
            String info,
            String length,
            HttpRequestResponse requestResponse,
            long startTimeMillis,
            long endTimeMillis
    ) {
        LogEntry entry;
        synchronized (logEntries) {
            entry = new LogEntry(
                    nextEntryId++,
                    name,
                    method,
                    url,
                    state,
                    info,
                    length,
                    requestResponse,
                    extractHost(url, requestResponse),
                    formatTime(startTimeMillis),
                    formatTime(endTimeMillis)
            );
            logEntries.add(entry);
        }

        SwingUtilities.invokeLater(() -> {
            if (enableFilterCheckBox == null || statusLabel == null) {
                return;
            }
            // 清除或删除可能先于该 EDT 回调执行，不能让已经删除的结果重新出现在表格中。
            if (!containsLogEntry(entry.id)) {
                return;
            }
            if (enableFilterCheckBox.isSelected()) {
                refreshTableOnEdt();
            } else if (findDisplayedRowById(entry.id) < 0) {
                int row = Udatas.size();
                Udatas.add(new TablesData(entry));
                fireTableRowsInserted(row, row);
                updateStatusLabel();
            }
        });
    }

    /** 将毫秒时间戳转换为结果表使用的本地时间文本。 */
    private String formatTime(long timeMillis) {
        if (timeMillis <= 0) {
            return "";
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(timeMillis));
    }

    /**
     * URL 异常时回退到 Montoya 的 HttpService，避免脏数据把所有结果错误归入同一主机。
     */
    private String extractHost(String url, HttpRequestResponse requestResponse) {
        try {
            String host = new URL(url).getHost();
            if (host != null && !host.trim().isEmpty()) {
                return host;
            }
        } catch (Exception ignored) {
            // 继续使用请求对象中的服务信息兜底。
        }
        try {
            if (requestResponse != null && requestResponse.httpService() != null) {
                String host = requestResponse.httpService().host();
                if (host != null && !host.trim().isEmpty()) {
                    return host;
                }
            }
        } catch (Throwable ignored) {
            // 第三方请求对象实现异常时仍允许结果进入列表。
        }
        return "<unknown>";
    }

    /** 检查异步 UI 回调对应的历史记录是否仍然存在。 */
    private boolean containsLogEntry(int entryId) {
        synchronized (logEntries) {
            for (LogEntry entry : logEntries) {
                if (entry.id == entryId) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 获取历史记录快照，避免在持锁期间操作 Swing 模型。 */
    private List<LogEntry> snapshotLogEntries() {
        synchronized (logEntries) {
            return new ArrayList<LogEntry>(logEntries);
        }
    }

    /** 按 Host 和响应长度统计重复次数。 */
    private Map<String, Map<String, Integer>> countSizesByHost(List<LogEntry> entries) {
        Map<String, Map<String, Integer>> counts = new HashMap<String, Map<String, Integer>>();
        for (LogEntry entry : entries) {
            Map<String, Integer> sizeCounts = counts.computeIfAbsent(entry.host, key -> new HashMap<String, Integer>());
            String size = normalizeLength(entry.length);
            sizeCounts.put(size, sizeCounts.getOrDefault(size, 0) + 1);
        }
        return counts;
    }

    /** 统一长度文本，空值也可以安全参与过滤。 */
    private String normalizeLength(String length) {
        return length == null ? "" : length.trim();
    }

    /** 根据当前重复阈值判断结果是否应显示。 */
    private boolean shouldShowEntry(LogEntry entry, Map<String, Map<String, Integer>> counts, int threshold) {
        Map<String, Integer> sizeCounts = counts.get(entry.host);
        if (sizeCounts == null) {
            return true;
        }
        return sizeCounts.getOrDefault(normalizeLength(entry.length), 0) <= threshold;
    }

    private void refreshTable() {
        if (SwingUtilities.isEventDispatchThread()) {
            refreshTableOnEdt();
        } else {
            SwingUtilities.invokeLater(this::refreshTableOnEdt);
        }
    }

    /**
     * 仅在 Swing EDT 重建结果视图；历史数据本身不变，因此时间、编号和请求响应对象都会保留。
     */
    private void refreshTableOnEdt() {
        if (Utable == null || statusLabel == null) {
            return;
        }
        Integer selectedEntryId = getSelectedEntryId();
        List<LogEntry> entries = snapshotLogEntries();
        boolean filterEnabled = enableFilterCheckBox != null && enableFilterCheckBox.isSelected();
        int threshold = thresholdSpinner != null && thresholdSpinner.getValue() instanceof Number
                ? ((Number) thresholdSpinner.getValue()).intValue()
                : 5;
        Map<String, Map<String, Integer>> counts = filterEnabled
                ? countSizesByHost(entries)
                : Collections.emptyMap();

        Udatas.clear();
        for (LogEntry entry : entries) {
            if (!filterEnabled || shouldShowEntry(entry, counts, threshold)) {
                Udatas.add(new TablesData(entry));
            }
        }
        fireTableDataChanged();
        restoreSelection(selectedEntryId);
        updateStatusLabel();
    }

    /** 将当前视图行转换成稳定的历史记录编号。 */
    private Integer getSelectedEntryId() {
        int selectedViewRow = Utable.getSelectedRow();
        if (selectedViewRow < 0) {
            return null;
        }
        int selectedModelRow = Utable.convertRowIndexToModel(selectedViewRow);
        if (selectedModelRow < 0 || selectedModelRow >= Udatas.size()) {
            return null;
        }
        return Udatas.get(selectedModelRow).id;
    }

    /** 刷新后按稳定编号恢复选中行。 */
    private void restoreSelection(Integer entryId) {
        if (entryId == null) {
            return;
        }
        int modelRow = findDisplayedRowById(entryId);
        if (modelRow >= 0) {
            int viewRow = Utable.convertRowIndexToView(modelRow);
            if (viewRow >= 0) {
                Utable.setRowSelectionInterval(viewRow, viewRow);
            }
        }
    }

    /** 在当前过滤视图中查找指定历史记录。 */
    private int findDisplayedRowById(int entryId) {
        for (int i = 0; i < Udatas.size(); i++) {
            if (Udatas.get(i).id == entryId) {
                return i;
            }
        }
        return -1;
    }

    private void clearHistory() {
        if (top == null || statusLabel == null || HRequestTextEditor == null || HResponseTextEditor == null) {
            return;
        }
        int result = JOptionPane.showConfirmDialog(top, t("confirm.clearHistory"), t("dialog.clearConfirm"), JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result == JOptionPane.YES_OPTION) {
            clearHistoryData();
        }
    }

    public void clearDisplayedHistory() {
        clearHistory();
    }

    /**
     * “清空全部历史”同时清理数据源和当前视图，避免刷新后被删除的记录再次出现。
     */
    private void clearHistoryData() {
        synchronized (logEntries) {
            logEntries.clear();
        }
        Udatas.clear();
        currentlyDisplayedItem = null;
        fireTableDataChanged();
        clearMessageEditors();
        updateStatusLabel();
    }

    public void removeSelectedRows() {
        if (Utable == null) {
            return;
        }
        int[] selectedRows = Utable.getSelectedRows();
        Set<Integer> entryIds = new HashSet<Integer>();
        for (int viewRow : selectedRows) {
            int modelRow = Utable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < Udatas.size()) {
                entryIds.add(Udatas.get(modelRow).id);
            }
        }
        if (entryIds.isEmpty()) {
            return;
        }
        synchronized (logEntries) {
            logEntries.removeIf(entry -> entryIds.contains(entry.id));
        }
        currentlyDisplayedItem = null;
        clearMessageEditors();
        refreshTableOnEdt();
    }

    /** 清空结果页的请求和响应详情。 */
    private void clearMessageEditors() {
        if (HRequestTextEditor != null) {
            HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
        }
        if (HResponseTextEditor != null) {
            HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
        }
    }

    private void updateStatusLabel() {
        if (statusLabel == null) {
            return;
        }
        int total;
        synchronized (logEntries) {
            total = logEntries.size();
        }
        statusLabel.setText(t("status.records", Udatas.size(), total));
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 9;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return t("table.result.name");
            case 2:
                return t("table.result.method");
            case 3:
                return t("table.result.url");
            case 4:
                return t("table.result.status");
            case 5:
                return t("table.result.info");
            case 6:
                return t("table.result.length");
            case 7:
                return t("table.result.start");
            case 8:
                return t("table.result.end");
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.ruleName;
            case 2:
                return datas.method;
            case 3:
                return datas.url;
            case 4:
                return datas.status;
            case 5:
                return datas.info;
            case 6:
                return datas.size;
            case 7:
                return datas.startTime;
            case 8:
                return datas.endTime;
            default:
                return "";
        }
    }

    public class URLTable extends JTable {
        private final TableRowSorter<TableModel> sorter;

        public URLTable(TableModel tableModel) {
            super(tableModel);
            sorter = new TableRowSorter<TableModel>(tableModel);
            setRowSorter(sorter);
            getTableHeader().addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int columnIndex = getColumnModel().getColumnIndexAtX(e.getX());
                        if (columnIndex >= 0) {
                            toggleSortOrder(columnIndex);
                        }
                    }
                }
            });
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row < 0 || row >= getRowCount()) {
                return;
            }
            int modelRow = convertRowIndexToModel(row);
            if (modelRow < 0 || modelRow >= Tags.this.Udatas.size()) {
                return;
            }
            TablesData dataEntry = Tags.this.Udatas.get(modelRow);
            currentlyDisplayedItem = dataEntry.requestResponse;
            if (currentlyDisplayedItem == null || currentlyDisplayedItem.request() == null) {
                clearMessageEditors();
            } else {
                HRequestTextEditor.setRequest(currentlyDisplayedItem.request());
            }
            if (currentlyDisplayedItem != null && currentlyDisplayedItem.hasResponse()) {
                HResponseTextEditor.setResponse(currentlyDisplayedItem.response());
            } else {
                HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
            }
            super.changeSelection(row, col, toggle, extend);
        }

        public void toggleSortOrder(int columnIndex) {
            if (columnIndex < 0 || columnIndex >= getColumnCount()) {
                return;
            }
            if (columnIndex == 4 || columnIndex == 6) {
                sorter.setComparator(columnIndex, (Comparator<String>) Tags.this::compareNumericStrings);
            } else {
                sorter.setComparator(columnIndex, Comparator.nullsFirst(Comparator.naturalOrder()));
            }

            List<? extends RowSorter.SortKey> sortKeys = sorter.getSortKeys();
            if (sortKeys.isEmpty()) {
                sorter.toggleSortOrder(columnIndex);
            } else {
                RowSorter.SortKey sortKey = sortKeys.get(0);
                if (sortKey.getColumn() == columnIndex) {
                    sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(columnIndex, sortKey.getSortOrder() == SortOrder.ASCENDING ? SortOrder.DESCENDING : SortOrder.ASCENDING)));
                } else {
                    sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(columnIndex, SortOrder.ASCENDING)));
                }
            }
        }
    }

    /**
     * 状态码和长度列优先按数字排序；遇到空值或异常文本时回退到字符串排序，避免 EDT 抛异常。
     */
    private int compareNumericStrings(String left, String right) {
        Long leftNumber = parseLong(left);
        Long rightNumber = parseLong(right);
        if (leftNumber != null && rightNumber != null) {
            return leftNumber.compareTo(rightNumber);
        }
        if (leftNumber != null) {
            return -1;
        }
        if (rightNumber != null) {
            return 1;
        }
        String safeLeft = left == null ? "" : left;
        String safeRight = right == null ? "" : right;
        return safeLeft.compareTo(safeRight);
    }

    /** 安全解析排序字段；非法内容返回空值并由比较器降级处理。 */
    private Long parseLong(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Long.valueOf(value.trim());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    /** 结果表使用的不可变显示行。 */
    public static class TablesData {
        final int id;
        final String ruleName;
        final String method;
        final String url;
        final String status;
        final String info;
        final String size;
        final HttpRequestResponse requestResponse;
        final String startTime;
        final String endTime;

        public TablesData(int id, String ruleName, String method, String url, String status, String info, String size, HttpRequestResponse requestResponse, String startTime, String endTime) {
            this.id = id;
            this.ruleName = ruleName;
            this.method = method;
            this.url = url;
            this.status = status;
            this.info = info;
            this.size = size;
            this.requestResponse = requestResponse;
            this.startTime = startTime;
            this.endTime = endTime;
        }

        /**
         * 从历史数据创建显示行时完整复制不可变字段，尤其不能丢失开始和结束时间。
         */
        public TablesData(LogEntry entry) {
            this(
                    entry.id,
                    entry.name,
                    entry.method,
                    entry.url,
                    entry.state,
                    entry.info,
                    entry.length,
                    entry.requestResponse,
                    entry.startTime,
                    entry.endTime
            );
        }
    }

    /** 结果历史的数据源，过滤和刷新不会修改其中的业务字段。 */
    public static class LogEntry {
        public final int id;
        public final String name;
        public final String method;
        public final String url;
        public final String state;
        public final String info;
        public final String length;
        public final HttpRequestResponse requestResponse;
        public final String host;
        public final String startTime;
        public final String endTime;

        /** 创建包含稳定编号和完整时间信息的历史记录。 */
        public LogEntry(
                int id,
                String name,
                String method,
                String url,
                String state,
                String info,
                String length,
                HttpRequestResponse requestResponse,
                String host,
                String startTime,
                String endTime
        ) {
            this.id = id;
            this.name = name;
            this.method = method;
            this.url = url;
            this.state = state;
            this.info = info;
            this.length = length;
            this.requestResponse = requestResponse;
            this.host = host;
            this.startTime = startTime;
            this.endTime = endTime;
        }
    }

    private void jTable1MouseClicked(MouseEvent evt) {
        if (evt.getButton() == MouseEvent.BUTTON3) {
            int focusedRowIndex = this.Utable.rowAtPoint(evt.getPoint());
            if (focusedRowIndex != -1) {
                if (!this.Utable.isRowSelected(focusedRowIndex)) {
                    this.Utable.setRowSelectionInterval(focusedRowIndex, focusedRowIndex);
                }
                m_popupMenu.show(this.Utable, evt.getX(), evt.getY());
            }
        }
    }
}

class Remove_All implements ActionListener {
    private final Tags tag;

    public Remove_All(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        tag.clearDisplayedHistory();
    }
}

class Remove_action implements ActionListener {
    private final Tags tag;

    public Remove_action(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        tag.removeSelectedRows();
    }
}
