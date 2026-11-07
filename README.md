# NetGuard — 校园网断网自动守护（Windows）

无人值守挂机场景的自愈脚本：**探测断网 → 关闭名单程序防真实 IP 泄露 → 无头浏览器自动登录校园网认证页 → 认证救不回来才（弹窗倒计时后）重启**，全程保护后台训练任务与远控软件，严防重启死循环。

> 适用前提：Windows 10/11 + 校园网为「网页表单登录（账号密码，无验证码）」+ 远控软件随登录自启。只要认证页是普通表单，改配置即可适配其他学校。

## 特性

- 🔍 **真实数据往返探测**：TCP+TLS/HTTP 直连中立 CDN，免疫两类误判——Clash TUN 本地假握手、校园网未认证时放行检测类 IP（223.5.5.5 等）
- 🌐 **自动认证**：无头浏览器填账号密码、点登录；以连通性探测结果为准，不依赖页面 DOM；逐字输入+自动化特征抹除；每日次数上限防账号锁定
- 🛡️ **隐私保护**：断网时按名单关闭浏览器/IM/代理等程序，防止网络恢复瞬间以真实 IP 发流量；白名单（远控、训练任务）永杀
- 🧠 **任务保护**：检测到 python 等训练进程 → 不重启（训练多为本地任务），只关其他程序+继续认证
- 🔁 **防重启死循环三重兜底**：30 分钟冷却 + 24h 次数上限 + 60s 可取消弹窗
- 🖥️ **托盘图标**：绿=在线·正式 / 黄=在线·演练 / 红=断网处理中；右键可开日志、改配置、重载
- 🧰 **适配工具**：`--dump-page` 打印认证页表单结构、`--test-auth` 手动测试认证、`--refresh-probe` 刷新探测 IP

## 工作流程

```
每 30s 探测（百度/腾讯/京东 CDN IP 的 TLS 握手，任一真实往返成功即在线）
 └─ 连续 3 次全失败 → 判定断网（约 2~2.5 分钟，过滤瞬时抖动）
     ├─ 启动宽限期(开机180s) / 重启冷却期(30min) / 用户取消抑制期(2h)内 → 仅记录
     ├─ 有训练任务（task_processes 进程在跑）→ 不重启：杀 kill_apps 名单进程 → 自动认证
     └─ 无任务 → 杀名单进程 → 先自动认证一次
           ├─ 认证成功 → 恢复，结束
           └─ 失败 → 弹置顶倒计时窗口(60s，人在机器前可取消)
                 ├─ 取消 → 2h 内不再弹/不重启
                 └─ 无人取消（锁屏/离开）→ shutdown /r /t 5 /f
重启后：随登录自启，冷却期内不再重启，持续自动认证直到联网。
```

## 快速开始

```bat
git clone https://github.com/<you>/NetGuard.git
cd NetGuard
install.bat          :: 自动建环境(env\)、下载 Chromium(browsers\)、注册开机自启
```

1. 编辑 `config.json`（首次运行自动生成，或复制 `config.example.json`）：
   - `portal_url`：校园网认证页地址。**找法**：断网状态下浏览器随便开个 http 站点，复制被跳转到的地址；或留空，脚本会访问 `http://www.msftconnecttest.com/redirect` 借助校园网 302 劫持自动跳到认证页
   - `campus_account` / `campus_password`：校园网账密（明文存本机，自行注意权限）
   - `never_kill`：确认包含你的远控软件进程名
2. 测试与适配（见下节）
3. `dry_run` 改为 `false` 正式启用；改完配置用托盘「重载配置并重启」生效

## 其他学校适配指南

| 步骤 | 命令/操作 | 说明 |
|---|---|---|
| 1. 看认证页结构 | `python net_guard.py --dump-page` | 打印所有输入框(type/name/id/placeholder/可见性)和按钮，截图存 `logs/shots/` |
| 2. 配置选择器 | config 的 `username_selector` 等 3 项 | 默认自动识别（user/账号/学号 等常见模式+兜底），识别失败时把 `--dump-page` 看到的 id/name 填进去，如 `#username` |
| 3. 测试认证 | `python net_guard.py --test-auth` | 不杀进程不重启，真实执行一次登录；已登录状态下以「网络可达」通过 |
| 4. 刷新探测 IP | `python net_guard.py --refresh-probe` | 联网状态下重新解析百度/腾讯/京东 IP 并写回配置（CDN 变更/换地区时用） |

**验证码说明**：若学校给密码登录加了图形/短信验证码，自动化无法通过（也不应该绕过），脚本会失败、退避并留截图，需手动登录。脚本定位是「无验证码表单认证」的自动恢复。

## 配置字段（config.json）

| 键 | 默认 | 说明 |
|---|---|---|
| `dry_run` | `true` | 演练模式：只记日志，不杀进程/不弹窗/不重启 |
| `probe_targets` | 3×CDN IP | IP 直连探测目标，第 3 项为 TLS SNI；任一真实往返成功即在线 |
| `fail_threshold` / `probe_interval_sec` | 3 / 30 | 连续失败次数阈值与探测间隔 |
| `boot_grace_sec` | 180 | 开机宽限期，网络栈未就绪时不动作 |
| `portal_url` / `campus_account` / `campus_password` | 空 | 认证页与账密 |
| `username_selector` / `password_selector` / `submit_selector` | 空 | 自定义 CSS 选择器，留空自动识别 |
| `auth_retry_min` / `auth_retry_max_min` | 5 / 30 | 认证失败退避间隔（指数增长） |
| `max_auth_per_day` | 10 | 每日自动认证上限，防账号锁定 |
| `task_processes` / `task_ignore_cmdline` | python 等 / workbuddy | 视为「训练任务」的进程名；命令行命中忽略串的不算（常驻服务） |
| `never_kill` | 常见远控+python | 白名单，**务必包含你的远控软件** |
| `kill_apps` | clash 系/浏览器/IM 等 | 断网时关闭的名单，精确匹配进程名（不含 .exe） |
| `auth_before_reboot` | `true` | 无任务时先试认证再重启 |
| `reboot_countdown_sec` / `cancel_suppress_min` | 60 / 120 | 重启弹窗时长 / 取消后抑制时长 |
| `reboot_cooldown_min` / `max_reboots_per_24h` | 30 / 3 | 防重启死循环 |
| `headless` | `true` | 认证用无头浏览器 |
| `tray_promoted` | `false` | 托盘图标位置：false=折叠区，true=任务栏常驻 |
| `heartbeat_min` | 30 | 在线心跳日志间隔，确认脚本活着 |

## 托盘与日志

- 托盘右键：**打开日志文件夹 / 打开配置文件 / 重载配置并重启 / 退出**；改配置后用「重载」立即生效
- `logs/netguard.log`：全部动作与原因推测（5MB 轮转）；`logs/shots/`：认证前后截图（认证失败先看这里）

## 卸载

`uninstall.bat` 删除自启注册（任务计划/HKCU Run 二选一都会清），再删整个文件夹即可。

## 常见问题

- **Q：会被反爬/封号吗？** 频率只有断网时一次+退避+每日上限，本人账号本机登录，属正常使用。若学校加验证码则需手动一次。
- **Q：Clash TUN 开着能正常工作吗？** 能。TLS 往返探测识破 TUN 假握手；认证浏览器强制直连（`--no-proxy-server`），规避「Clash 被杀后系统代理残留」与「代理 REJECT 规则拦截认证页」。
- **Q：重启后停在锁屏怎么办？** 建议开启 Windows 自动登录（netplwiz）；若远控是服务级（可锁屏连入），登录后脚本即接管。
- **Q：个别安全软件会拦无头浏览器访问认证页（ERR_BLOCKED_BY_CLIENT）？** 脚本默认用 Playwright 内置 Chromium 并带一次重试；仍失败时在安全软件里放行，或临时退出安全软件测试。

## 免责声明

仅供个人在本人设备、本人账号上自动化校园网认证与断网恢复，请遵守所在学校/单位网络使用规定。因使用本脚本造成的任何后果由使用者自行承担。

---

**English TL;DR**: NetGuard is a Windows tray-resident daemon for unattended campus-network machines. It probes connectivity with real TLS/HTTP round-trips (immune to Clash-TUN fake handshakes and gateway-whitelisted probe IPs), closes privacy-sensitive apps on outage, auto-re-authenticates the captive portal with a headless browser (no-CAPTCHA form logins), and reboots — with a cancellable 60s dialog — only as a last resort. Training/remote-control processes are whitelisted; reboot loops are guarded by cooldown + daily cap. Configure everything in `config.json`; run `install.bat` to set up.
