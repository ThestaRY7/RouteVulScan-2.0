README Version: [English](README_EN.md)

# RouteVulScan

RouteVulScan 是一个基于 Burp Suite Montoya API 开发的被动式路径漏洞探测插件。

它的目标不是做大规模目录爆破，而是在你正常测试业务流量时，递归提取每一层路径，按规则发起少量、高价值探测请求，再通过状态码和正则表达式判断是否命中常见弱点，例如配置泄露、调试接口暴露、备份文件、历史遗留敏感资源等。
## 功能截图
<img width="1460" height="900" alt="image" src="https://github.com/user-attachments/assets/91f2c09b-bfd8-4c4b-a7c1-eeac29f196a0" />
<img width="1458" height="878" alt="image" src="https://github.com/user-attachments/assets/fcd82360-d563-4e7a-b1c7-754c8c13ca57" />

“代次” 指的是当前扫描会话的“版本号”或“取消代号”。

在这个插件里，每次点击“取消运行中扫描”都会把内部的 scanGeneration 加 1，代码在 BurpExtender.java (line 165)。进度面板显示的“代次”来自同一个计数器，见 Config.java (line 332)。
含义很简单：

- 代次 0：初始状态，还没执行过“取消运行中扫描”
- 代次 1：至少取消过一次，后续新任务属于第 1 代
- 代次 2：取消过两次，以此类推

这个字段主要是给内部并发扫描做“旧任务失效”判断用的，不是漏洞数，也不是线程数。对日常使用来说，可以把它理解为“当前扫描批次编号”。


## 项目来源

本仓库基于原始项目二次维护与兼容性修复：

- 原版 GitHub 仓库：[F6JO/RouteVulScan](https://github.com/F6JO/RouteVulScan)

## 这个插件有什么用

- 被动扫描当前流经 Burp 的请求与响应，不要求你额外维护字典或手工逐个跑目录。
- 递归探测每一层路径，例如访问 `/a/b/c` 时，可继续检查 `/`、`/a/`、`/a/b/`、`/a/b/c/`。
- 按 YAML 规则库匹配状态码、关键字和自定义正则，快速发现“量不大但很容易漏掉”的问题。
- 支持右键把请求发送到插件做主动补扫，适合聚焦单站点做深入排查。
- 支持规则分组、启停控制、请求头继承、域名扫描、绕过扫描、结果过滤和历史查看。

## 适用场景

- 正常做 Web 渗透测试时，希望顺手捞出隐藏接口、敏感文件、调试页面。
- 不想跑重型爆破，但又不想漏掉各层路径下的高价值遗留资源。
- 需要一套可编辑、可扩展、可版本化维护的 Burp 本地规则库。

## 主要功能

- 被动扫描：流量经过 Burp 时自动触发扫描。
- 主动扫描：右键选中请求，发送到 RouteVulScan。
- 规则引擎：规则存储在 `Config_yaml.yaml`，支持分类、启用状态、正则和状态码范围。
- 请求模板变量：规则中可以引用原始请求/响应中的字段。
- 扫描控制：支持线程数、主机过滤、携带请求头、域名扫描、绕过扫描。
- 结果面板：展示命中结果、请求包、响应包，并支持过滤相同响应长度的重复项。

## 技术选型

- 当前版本优先：使用 Burp 官方主线 **Montoya API**。
- 官方推荐优先：使用 **Swing + Montoya UI 组件** 构建插件界面。
- 生产可运行为目标：使用 **Maven + Shade Plugin** 打包生成可直接导入 Burp 的 fat jar。
- 放弃旧方案原因：不再使用旧版 `IBurpExtender` / `ITab`，也不再维护历史 Gradle 构建链路。

## 环境要求

- Burp Suite 2023.12.1及以上
- JDK 17
- Maven 3.9+

## 构建方式

```bash
mvn clean package
```

构建完成后，产物位于：

```bash
target/RouteVulScan-burp.jar
```

## 安装方式

在 Burp Suite 中打开：

```text
Extender -> Extensions -> Add
```

选择 `target/RouteVulScan-burp.jar` 即可加载。

## 使用说明

1. 在 Burp 中加载插件。
2. 插件首次启动后会在当前运行目录生成或使用 `Config_yaml.yaml`。
3. 在配置页开启你需要的开关，例如被动扫描、携带请求头、域名扫描。
4. 正常测试目标站点，插件会自动递归检查各层路径。
5. 在结果页查看命中记录，并联动查看请求和响应。
6. 如需针对某个站点补扫，可右键请求发送到 RouteVulScan。

## 规则说明

规则文件为 `Config_yaml.yaml`，每条规则可定义：

- `type`：规则组
- `loaded`：是否启用
- `name`：规则名称
- `method`：请求方法
- `url`：路径后缀
- `re`：匹配正则
- `info`：命中说明
- `state`：状态码，可写单值、逗号分隔、区间范围

### 模板变量

规则中支持引用当前请求或响应的信息：

```text
{{request.head.cookie}}
{{request.head.host.main}}
{{request.head.host.name}}
{{request.method}}
{{request.path}}
{{request.url}}
{{request.protocol}}
{{request.port}}
{{response.head.server}}
{{response.status}}
```

## 致谢

- 原作者：F6JO

[![Stargazers over time](https://starchart.cc/ThestaRY7/RouteVulScan-2.0.svg?variant=adaptive)](https://starchart.cc/ThestaRY7/RouteVulScan-2.0)



## 免责声明

本工具仅用于企业自身安全建设、甲方授权范围内的安全检测与风险排查，项目开发目的在于帮助甲方提升自身业务系统的安全防护能力。任何个人或组织在使用本工具前，应确保已获得目标系统的合法授权，并遵守所在国家或地区的相关法律法规。

任何人因下载、安装、传播、使用或二次开发本工具所造成的任何直接或间接问题、损失、纠纷、违法违规后果，均由使用者自行承担，与原作者及项目维护者无关。原作者及项目维护者不对任何未授权测试、攻击行为或其他不当使用承担任何责任。
