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
            updateStatusLabel();
        });
    }

    private String extractHost(String url) {
        try {
            return new URL(url).getHost();
        } catch (Exception e) {
            return t("status.unknown");
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
            updateStatusLabel();
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
        int result = JOptionPane.showConfirmDialog(top, t("confirm.clearHistory"), t("dialog.clearConfirm"), JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
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
            updateStatusLabel();
        }
    }

    public void clearDisplayedHistory() {
        while (Udatas.size() != 0) {
            Udatas.remove(0);
            fireTableRowsDeleted(0, 0);
        }
        HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
        HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
        updateStatusLabel();
    }

    public void removeSelectedRows() {
        int[] remId = Utable.getSelectedRows();
        for (int i : reversal(remId)) {
            Udatas.remove(i);
            fireTableRowsDeleted(i, i);
            HRequestTextEditor.setRequest(HttpRequest.httpRequest(""));
            HResponseTextEditor.setResponse(HttpResponse.httpResponse(""));
        }
        updateStatusLabel();
    }

    private Integer[] reversal(int[] intArray) {
        Integer[] newScores = new Integer[intArray.length];
        for (int i = 0; i < intArray.length; i++) {
            newScores[i] = intArray[i];
        }
        Arrays.sort(newScores, Collections.reverseOrder());
        return newScores;
    }

    private void updateStatusLabel() {
        statusLabel.setText(t("status.records", Udatas.size(), logEntries.size()));
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

            if (columnIndex == 4 || columnIndex == 6) {
                sorter.setComparator(columnIndex, Comparator.comparingInt((String value) -> Integer.parseInt(value.trim())));
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
