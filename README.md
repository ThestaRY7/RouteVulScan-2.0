README Version: [ENGLISH](README_EN.md)

# RouteVulScan

A passive recursive path probing extension for Burp Suite, built on the Montoya API with YAML-based detection rules and low-noise vulnerability checks during normal web security testing.

RouteVulScan 是一个基于 Burp Suite Montoya API 开发的被动式路径递归探测插件。它会在正常测试业务流量时，自动提取并递归检查每一层路径，结合 YAML 规则进行低噪声、高价值的漏洞探测。

## 功能截图
<img width="1460" height="901" alt="image" src="https://github.com/user-attachments/assets/0541b262-956f-4be2-bc7d-63e01caf9e39" />
<img width="1459" height="899" alt="image" src="https://github.com/user-attachments/assets/5967a91c-917d-4cf0-8d41-ef47ec40b189" />


“代次” 指的是当前扫描会话的“版本号”或“取消代号”。

在这个插件里，每次点击“取消运行中扫描”都会把内部的 scanGeneration 加 1，进度面板显示的“代次”来自同一个计数器。
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
- 支持规则分组、启停控制、请求头继承、云端下载规则、本地重载规则、结果过滤和历史查看。

## 适用场景

- 正常做 Web 渗透测试时，希望顺手捞出隐藏接口、敏感文件、调试页面。
- 不想跑重型爆破，但又不想漏掉各层路径下的高价值遗留资源。
- 需要一套可编辑、可扩展、可版本化维护的 Burp 本地规则库。

## 主要功能

- 被动扫描：流量经过 Burp 时自动触发扫描。
- 主动扫描：右键选中请求，发送到 RouteVulScan。
- 规则引擎：规则存储在 `Rules.yaml`，支持分类、启用状态、正则和状态码范围。
- 请求模板变量：规则中可以引用原始请求/响应中的字段。
- 扫描控制：支持线程数、主机过滤和携带请求头。
- 结果面板：展示命中结果、请求包、响应包，并支持过滤相同响应长度的重复项。

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
target/RouteVulScan-V2.0.3.jar
```

## 安装方式

在 Burp Suite 中打开：

```text
Extender -> Extensions -> Add
```

选择 `target/RouteVulScan-V2.0.3.jar` 即可加载。

## 使用说明

1. 在 Burp 中加载插件。
2. 插件首次启动后会在当前运行目录生成或使用 `Rules.yaml`。
3. 在配置页开启你需要的开关，例如被动扫描、携带请求头。
4. 正常测试目标站点，插件会自动递归检查各层路径。
5. 在结果页查看命中记录，并联动查看请求和响应。
6. 如需针对某个站点补扫，可右键请求发送到 RouteVulScan。

## 规则说明

规则文件为 `Rules.yaml`，每条规则可定义：

- `type`：规则组
- `loaded`：是否启用
- `name`：规则名称
- `method`：请求方法
- `url`：路径后缀
- `re`：匹配正则
- `info`：命中说明
- `state`：状态码，可写单值、逗号分隔、区间范围

## 致谢

- 原作者：F6JO

[![Stargazers over time](https://starchart.cc/ThestaRY7/RouteVulScan-2.0.svg?variant=adaptive)](https://starchart.cc/ThestaRY7/RouteVulScan-2.0)



## 免责声明

本工具仅用于企业自身安全建设、甲方授权范围内的安全检测与风险排查，项目开发目的在于帮助甲方提升自身业务系统的安全防护能力。任何个人或组织在使用本工具前，应确保已获得目标系统的合法授权，并遵守所在国家或地区的相关法律法规。

任何人因下载、安装、传播、使用或二次开发本工具所造成的任何直接或间接问题、损失、纠纷、违法违规后果，均由使用者自行承担，与原作者及项目维护者无关。原作者及项目维护者不对任何未授权测试、攻击行为或其他不当使用承担任何责任。
