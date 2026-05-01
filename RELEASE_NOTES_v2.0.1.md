# RouteVulScan v2.0.1 Release Notes

## Suggested Commit Message

```text
fix: reset scan state and add English language support
```

```text
fix: 修复扫描重置并新增英文语言支持
```

## 中文

### 更新概述

本次发布聚焦两个核心改进：修复“重置进度”后无法对同一网站重新扫描的问题，并新增 English Language Support。插件仍保持 Java 17、Maven、Burp Montoya API 2025.11 与 Swing 技术栈，继续面向当前 Burp 官方推荐的 Montoya 扩展 API。

### 主要变更

- 修复点击 `重置进度` 后再次访问同一网站不会触发新扫描的问题。
- 重置时会清空路径历史、被动 URL 去重缓存、域名去重缓存和扫描进度计数。
- 重置时会递增扫描代次并重建线程池，使旧扫描任务失效，避免旧任务污染新进度。
- 重置时会重新从当前 `Config_yaml.yaml` 加载规则，支持用户编辑规则后立即用最新版规则重新扫描。
- 新增 `中文` / `English` 语言切换，语言选择会通过 Burp Montoya preferences 持久保存。
- 新增 Java `ResourceBundle` 国际化资源，集中维护中英文 UI、菜单、弹窗、状态与常见日志文案。
- 更新 README 与 CHANGELOG，补充依赖、目录结构、入口文件、构建方式和运行方式。

### 注意事项

- `重置进度` 不会清空漏洞结果历史；如需清空结果，请继续使用结果页的 `清除历史`。
- YAML 规则内容不会被翻译，规则名称、路径、正则和 `info` 字段均保持用户自定义原文。

### 构建与运行

```bash
mvn clean package
```

构建产物：

```text
target/RouteVulScan-V2.0.1.jar
```

在 Burp Suite 中通过 `Extender -> Extensions -> Add` 加载该 jar 即可。

## English

### Overview

This release focuses on two improvements: fixing the reset behavior so the same website can be scanned again after resetting progress, and adding English Language Support. The extension keeps the current Java 17, Maven, Burp Montoya API 2025.11, and Swing stack, and continues to use Burp's current Montoya extension API.

### Changes

- Fixed an issue where clicking `Reset Progress` did not allow the same website to be scanned again.
- Reset now clears path history, passive URL de-duplication cache, domain de-duplication cache, and scan progress counters.
- Reset now increments the scan generation and rebuilds the thread pool so old scan tasks are invalidated and cannot pollute new progress.
- Reset now reloads rules from the current `Config_yaml.yaml`, allowing edited rules to take effect before rescanning the same target.
- Added `中文` / `English` language switching, persisted via Burp Montoya preferences.
- Added Java `ResourceBundle` i18n resources for UI labels, menus, dialogs, status text, and common log messages.
- Updated README and CHANGELOG with dependencies, directory structure, entry point, build instructions, and runtime usage.

### Notes

- `Reset Progress` does not clear finding history. Use `Clear History` in the findings tab when you want to clear previous results.
- YAML rule content is not translated. Rule names, paths, regexes, and `info` fields remain user-authored content.

### Build and Run

```bash
mvn clean package
```

Build artifact:

```text
target/RouteVulScan-V2.0.1.jar
```

Load the jar in Burp Suite via `Extender -> Extensions -> Add`.
