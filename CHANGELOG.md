# Changelog

## 2026-05-06 / v2.0.2

### 修复

- 修复右键 `发送到 RouteVulScan 并携带请求头` 未真实继承当前请求头的问题。
- 修复右键选择 POST 请求并携带请求头时，扫描请求仍被从零构造为 GET，导致 Logger 中缺失原 POST 方法、请求体与请求头的问题。
- 现在右键携带请求头扫描会以当前选中的请求作为模板，仅替换扫描路径，保留原始方法、body、Cookie、Authorization 与自定义 header。
- 修复右键扫描在 Swing 事件线程同步执行导致 Burp UI 卡住的问题；扫描流程改为后台调度执行。
- 修复被动扫描在 Burp HTTP 回调线程同步执行的问题，避免阻塞代理流量处理。

### 构建

- 版本更新为 `v2.0.2`。
- Maven Shade 产物更新为 `target/RouteVulScan-V2.0.2.jar`。

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

### 文档

- 重写 `README.md`，补充插件用途、功能、安装方法、构建方法和规则说明。
- 新增本更新日志文档，便于后续发布到 GitHub 时追踪版本变化。
- 新增 `RELEASE_NOTES.md`，用于 GitHub Release 发布说明。
- 新增 `LICENSE` 来源与授权说明文件，并标注原版仓库地址：`https://github.com/F6JO/RouteVulScan`。
