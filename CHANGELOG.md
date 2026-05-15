# Changelog

## 2026-05-15 / v2.0.3

### 修复

- 修复 Burp 右键扩展菜单显示为 `Route Vulnerable Scan 2.0.0` 的问题，扩展名统一调整为 `RouteVulScan`。
- 修复右键 `发送到 RouteVulScan 并携带请求头` 行为不符合预期的问题；现在该入口会直接使用当前选中的请求作为扫描模板，不再弹出自定义请求头编辑窗口。
- 修复携带请求头扫描时重新构造请求导致原始业务 header 丢失的问题；现在扫描请求仅替换 URL path，保留原请求中的 `Host`、`Content-Type`、`Content-Length`、认证 header、自定义 header 与其他 request headers。
- 保持规则方法逻辑不变：GET 规则仍发送 GET 请求，POST 规则仍发送 POST 请求，同时复用原始请求头上下文。

## 2026-05-06 / v2.0.2

### 修复

- 修复右键 `发送到 RouteVulScan 并携带请求头` 未真实继承当前请求头的问题。
- 修复右键选择 POST 请求并携带请求头时，扫描请求仍被从零构造为 GET，导致 Logger 中缺失原 POST 方法、请求体与请求头的问题。
- 现在右键携带请求头扫描会以当前选中的请求作为模板，仅替换扫描路径，保留原始方法、body、Cookie、Authorization 与自定义 header。
- 修复右键扫描在 Swing 事件线程同步执行导致 Burp UI 卡住的问题；扫描流程改为后台调度执行。
- 修复被动扫描在 Burp HTTP 回调线程同步执行的问题，避免阻塞代理流量处理。
- 修复云端规则下载完成后在后台线程直接刷新 Swing UI 的问题；规则列表刷新与弹窗统一切回 Swing EDT 执行。
- 修复重复点击 `云端下载规则` 会创建多个下载线程的问题；现在同一时间只允许一个云端规则下载任务运行。
- 云端规则下载改用 Java 17 `HttpClient`，设置连接超时与请求超时，避免网络异常时下载线程长期阻塞。

### 移除

- 移除 `域名扫描` 模块，包括配置页开关、扫描逻辑、域名去重状态与相关中英文文案。
- 移除 `绕过扫描` 模块，包括路径绕过请求变体、配置页开关与相关中英文文案。
- 移除规则文件中的 `Bypass_List` 参数；规则读写与云端合并流程均不再保留该字段。

### 变更

- 规则文件从 `Config_yaml.yaml` 重命名为 `Rules.yaml`，插件启动、规则读取、规则写入与文档说明均改为使用新文件名。
- `更新规则` 按钮重命名为 `云端下载规则`，英文文案为 `Cloud Download Rules`。
- `重新加载规则` 按钮重命名为 `本地重载规则`，英文文案为 `Local Reload Rules`。
- `云端下载规则` 现在从 `https://raw.githubusercontent.com/ThestaRY7/RouteVulScan-2.0/main/Rules.yaml` 下载规则，并校验 HTTP 状态码与规则内容有效性。
- 扫描调度与规则请求执行分离：新增独立扫描协调线程，规则请求继续使用可配置工作线程池，避免协调任务与规则任务互相阻塞。

## 2026-04-30 / v2.0.1

### 修复

- 修复点击 `重置进度` 后再次访问同一网站不会重新扫描的问题。
- 现在重置会递增扫描代次、重置线程池、清空路径/URL/域名去重状态、清空进度计数，并重新从当前 `Config_yaml.yaml` 加载规则。
- 重置操作不会清空漏洞结果历史；结果历史仍由结果页的 `清除历史` 独立管理。

### 新增

- 新增 English Language Support，配置页可在 `中文` / `English` 之间切换。
- 语言选择通过 Burp Montoya `preferences()` 持久保存，重启 Burp 或重载插件后保持上次选择。
- 新增 `src/main/resources/i18n/messages_zh_CN.properties` 与 `messages_en_US.properties`，集中维护中英文界面文案。
- 调整 Maven Shade 产物命名，后续统一输出 `target/RouteVulScan-V<当前版本>.jar`，例如 `target/RouteVulScan-V2.0.1.jar`。

## 2026-04-06 / v2.0.0

### 修复

- 修复 Burp Suite 2025.10.7 加载插件时报错 `java.lang.IllegalArgumentException: Component cannot be null`。
- 根因是 `UI.Tags` 在构造函数中异步初始化界面，`BurpExtender.initialize()` 在界面根组件尚未创建完成时就调用了 `registerSuiteTab()`。
- 现在改为同步构建 UI 根组件，并在注册前显式校验组件非空，避免初始化时序问题再次出现。

### 构建与兼容性调整

- 保持 Burp 官方主线的 Montoya API，不回退到旧版 Extender API。
- 新增 Maven 构建文件 `pom.xml`，使用 `maven-shade-plugin` 打包。
- 构建目标固定为 JDK 17，适配当前 Burp 2025.x 运行环境。
- 打包产物统一为当时的 `target/RouteVulScan-burp.jar`。
- `montoya-api` 依赖改为 `provided`，避免把 Burp 自带 API 打入插件包。

### 清理

- 删除历史 Gradle 缓存与构建产物目录：`.gradle/`、`build/`。
- 删除 Maven 构建产物目录：`target/`，避免把本地打包结果提交到仓库。
- 删除 macOS 垃圾文件：`.DS_Store`。
- 删除历史 Gradle 构建文件 `build.gradle`，统一只保留 Maven 构建入口。
- 删除不再使用的 `lib/rt.jar` 历史遗留依赖目录。
