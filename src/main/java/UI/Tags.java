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
import javax.swing.table.TableColumnModel;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Tags extends AbstractTableModel {
    public final BurpExtender burp;
    public final Config config;

    private JSplitPane top;
    private JSplitPane splitPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;
    private JPopupMenu m_popupMenu;
    private JLabel statusLabel;
    private JCheckBox enableFilterCheckBox;
    private JLabel thresholdLabel;
    private JSpinner thresholdSpinner;
    public URLTable Utable;
    private JScrollPane UscrollPane;
    public List<TablesData> Udatas = new ArrayList<TablesData>();
    public HttpRequestEditor HRequestTextEditor;
    public HttpResponseEditor HResponseTextEditor;
    private HttpRequestResponse currentlyDisplayedItem;
    private List<LogEntry> logEntries = new ArrayList<LogEntry>();
    private Map<String, Map<Integer, Integer>> hostSizeCountMap = new HashMap<String, Map<Integer, Integer>>();

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

    private void buildUi() {
        try {
            this.top = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            JTabbedPane tabs = new JTabbedPane();
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            enableFilterCheckBox = new JCheckBox("启用重复 Size 过滤");
            enableFilterCheckBox.setSelected(false);
            enableFilterCheckBox.setToolTipText("启用后将过滤同一 Host 下相同响应长度的结果");
            enableFilterCheckBox.addActionListener(e -> refreshTable());

            thresholdLabel = new JLabel("重复阈值：");
            thresholdSpinner = new JSpinner(new SpinnerNumberModel(5, 2, 100, 1));
            thresholdSpinner.addChangeListener(e -> refreshTable());

            filterPanel.add(enableFilterCheckBox);
            filterPanel.add(thresholdLabel);
            filterPanel.add(thresholdSpinner);

            JButton refreshButton = new JButton("刷新显示");
            refreshButton.addActionListener(e -> refreshTable());
            filterPanel.add(refreshButton);

            JButton clearButton = new JButton("清除历史");
            clearButton.addActionListener(e -> clearHistory());
            filterPanel.add(clearButton);

            statusLabel = new JLabel("显示 0 / 0 条记录");
            filterPanel.add(statusLabel);

            Utable = new URLTable(this);
            UscrollPane = new JScrollPane(Utable);

            m_popupMenu = new JPopupMenu();
            JMenuItem delMenItem = new JMenuItem("删除选中项");
            delMenItem.addActionListener(new Remove_action(this));
            JMenuItem delAllMenItem = new JMenuItem("清空全部历史");
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
            Ltable.addTab("请求", HRequestTextEditor.uiComponent());
            Rtable.addTab("响应", HResponseTextEditor.uiComponent());
            HjSplitPane.add(Ltable, "left");
            HjSplitPane.add(Rtable, "right");

            splitPane.add(tablePanel, "left");
            splitPane.add(HjSplitPane, "right");
            tabs.addTab("漏洞结果", splitPane);
            tabs.addTab("配置", config.$$$getRootComponent$$$());
            top.setTopComponent(tabs);
            burp.api.userInterface().applyThemeToComponent(top);
        } catch (Throwable t) {
            BurpExtender.logStaticError("初始化结果标签页失败", t);
        }
    }

    public Component getUiComponent() {
        return this.top;
    }

    public void addLogEntry(String name, String method, String url, String state, String info, String length, HttpRequestResponse requestResponse) {
        String host = extractHost(url);
        LogEntry entry = new LogEntry(name, method, url, state, info, length, requestResponse, host);
        synchronized (logEntries) {
            logEntries.add(entry);
            updateHostSizeCount(host, Integer.parseInt(length));
        }

        SwingUtilities.invokeLater(() -> {
            if (enableFilterCheckBox == null || statusLabel == null) {
                return;
            }
            if (!enableFilterCheckBox.isSelected() || shouldShowEntry(entry)) {
                add(name, method, url, state, info, length, requestResponse);
            }
            statusLabel.setText("显示 " + Udatas.size() + " / " + logEntries.size() + " 条记录");
        });
    }

    private String extractHost(String url) {
        try {
            return new URL(url).getHost();
        } catch (Exception e) {
            return "未知";
        }
    }

    private void updateHostSizeCount(String host, int size) {
        synchronized (hostSizeCountMap) {
            if (!hostSizeCountMap.containsKey(host)) {
                hostSizeCountMap.put(host, new HashMap<Integer, Integer>());
            }
            Map<Integer, Integer> sizeMap = hostSizeCountMap.get(host);
            sizeMap.put(size, sizeMap.getOrDefault(size, 0) + 1);
        }
    }

    private boolean shouldShowEntry(LogEntry entry) {
        if (enableFilterCheckBox == null || thresholdSpinner == null) {
            return true;
        }
        if (!enableFilterCheckBox.isSelected()) {
            return true;
        }
        int threshold = (Integer) thresholdSpinner.getValue();
        synchronized (hostSizeCountMap) {
            if (hostSizeCountMap.containsKey(entry.host)) {
                Map<Integer, Integer> sizeMap = hostSizeCountMap.get(entry.host);
                return sizeMap.getOrDefault(Integer.parseInt(entry.length), 0) <= threshold;
            }
        }
        return true;
    }

    private void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            if (Utable == null || statusLabel == null) {
                return;
            }
            int selectedRow = Utable.getSelectedRow();
            Udatas.clear();
            recalculateHostSizeCount();
            synchronized (logEntries) {
                for (LogEntry entry : logEntries) {
                    if (shouldShowEntry(entry)) {
                        Udatas.add(new TablesData(entry.name, entry.method, entry.url, entry.state, entry.info, entry.length, entry.requestResponse));
                    }
                }
            }
            fireTableDataChanged();
            if (selectedRow >= 0 && selectedRow < Udatas.size()) {
                Utable.setRowSelectionInterval(selectedRow, selectedRow);
            }
            statusLabel.setText("显示 " + Udatas.size() + " / " + logEntries.size() + " 条记录");
        });
    }

    private void recalculateHostSizeCount() {
        synchronized (hostSizeCountMap) {
            hostSizeCountMap.clear();
            synchronized (logEntries) {
                for (LogEntry entry : logEntries) {
                    updateHostSizeCount(entry.host, Integer.parseInt(entry.length));
                }
            }
        }
    }

    private void clearHistory() {
        if (top == null || statusLabel == null || HRequestTextEditor == null || HResponseTextEditor == null) {
            return;
        }
        int result = JOptionPane.showConfirmDialog(top, "确定要清除所有历史记录吗？", "确认清除", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result == JOptionPane.YES_OPTION) {
            synchronized (logEntries) {
                logEntries.clear();
            }
            synchronized (hostSizeCountMap) {
                hostSizeCountMap.clear();
            }
            Udatas.clear();
            fireTableDataChanged();
            HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
            HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
            statusLabel.setText("显示 0 / 0 条记录");
        }
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
                return "漏洞名称";
            case 2:
                return "请求方法";
            case 3:
                return "URL";
            case 4:
                return "状态码";
            case 5:
                return "说明";
            case 6:
                return "长度";
            case 7:
                return "开始时间";
            case 8:
                return "结束时间";
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
                return datas.VulName;
            case 2:
                return datas.Method;
            case 3:
                return datas.url;
            case 4:
                return datas.status;
            case 5:
                return datas.Info;
            case 6:
                return datas.Size;
            case 7:
                return datas.startTime;
            case 8:
                return datas.endTime;
            default:
                return "";
        }
    }

    public int add(String vulName, String method, String url, String status, String info, String size, HttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            String startTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            int id = this.Udatas.size();
            this.Udatas.add(new TablesData(id, vulName, method, url, status, info, size, requestResponse, startTime, ""));
            fireTableRowsInserted(id, id);
            return id;
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
                        toggleSortOrder(columnIndex);
                    }
                }
            });
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = Tags.this.Udatas.get(convertRowIndexToModel(row));
            currentlyDisplayedItem = dataEntry.requestResponse;
            HRequestTextEditor.setRequest(currentlyDisplayedItem.request());
            if (currentlyDisplayedItem.hasResponse()) {
                HResponseTextEditor.setResponse(currentlyDisplayedItem.response());
            } else {
                HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
            }
            super.changeSelection(row, col, toggle, extend);
        }

        public void toggleSortOrder(int columnIndex) {
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

            String columnName = getColumnModel().getColumn(columnIndex).getHeaderValue().toString();
            if (columnName.equals("长度") || columnName.equals("状态码")) {
                sorter.setComparator(columnIndex, Comparator.comparingInt((String value) -> Integer.parseInt(value)));
            } else if (columnName.equals("开始时间")) {
                sorter.setComparator(columnIndex, Comparator.naturalOrder());
            } else {
                sorter.setComparator(columnIndex, Comparator.naturalOrder());
            }
        }
    }

    public static class TablesData {
        final int id;
        final String VulName;
        final String Method;
        final String url;
        final String status;
        final String Info;
        final String Size;
        final HttpRequestResponse requestResponse;
        final String startTime;
        final String endTime;

        public TablesData(int id, String VulName, String Method, String url, String status, String Info, String Size, HttpRequestResponse requestResponse, String startTime, String endTime) {
            this.id = id;
            this.VulName = VulName;
            this.Method = Method;
            this.url = url;
            this.status = status;
            this.Info = Info;
            this.Size = Size;
            this.requestResponse = requestResponse;
            this.startTime = startTime;
            this.endTime = endTime;
        }

        public TablesData(String name, String method, String url, String state, String info, String length, HttpRequestResponse requestResponse) {
            this(0, name, method, url, state, info, length, requestResponse, "", "");
        }
    }

    public static class LogEntry {
        public final String name;
        public final String method;
        public final String url;
        public final String state;
        public final String info;
        public final String length;
        public final HttpRequestResponse requestResponse;
        public final String host;

        public LogEntry(String name, String method, String url, String state, String info, String length, HttpRequestResponse requestResponse, String host) {
            this.name = name;
            this.method = method;
            this.url = url;
            this.state = state;
            this.info = info;
            this.length = length;
            this.requestResponse = requestResponse;
            this.host = host;
        }
    }

    private void jTable1MouseClicked(MouseEvent evt) {
        if (evt.getButton() == MouseEvent.BUTTON3) {
            int focusedRowIndex = this.Utable.rowAtPoint(evt.getPoint());
            if (focusedRowIndex != -1) {
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
        while (tag.Udatas.size() != 0) {
            tag.Udatas.remove(0);
            tag.fireTableRowsDeleted(0, 0);
        }
        tag.HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
        tag.HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
    }
}

class Remove_action implements ActionListener {
    private final Tags tag;

    public Remove_action(Tags tag) {
        this.tag = tag;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        int[] remId = tag.Utable.getSelectedRows();
        for (int i : reversal(remId)) {
            tag.Udatas.remove(i);
            tag.fireTableRowsDeleted(i, i);
            tag.HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
            tag.HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
        }
    }

    public Integer[] reversal(int[] int_array) {
        Integer[] newScores = new Integer[int_array.length];
        for (int i = 0; i < int_array.length; i++) {
            newScores[i] = int_array[i];
        }
        Arrays.sort(newScores, Collections.reverseOrder());
        return newScores;
    }
}
