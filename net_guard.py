#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetGuard —— 断网守护脚本
========================
场景：无人值守挂机 + 校园网(浏览器网页认证) + Clash Verge TUN(非开机自启) + 远控软件。

行为概要：
  1. 每 probe_interval_sec 秒用 TCP 直连公共 DNS 探测网络（不走 DNS 解析）。
  2. 连续 fail_threshold 次全部失败 → 判定断网：
     - 有训练任务(task_processes 进程在跑，排除本脚本自身) → 不重启：
       关闭 kill_apps 名单进程(白名单除外) + 自动认证校园网
     - 无任务 → 关闭名单进程 + 先尝试一次自动认证；
       认证失败则弹出置顶倒计时窗口(可取消)，无人取消才真正重启
  3. 重启后(自动登录)脚本随登录自启：冷却期内不再重启，持续自动认证直到联网。
  4. 防重启死循环三重兜底：冷却期 / 24h 次数上限 / 用户取消抑制期。

配置：config.json（首次运行自动生成默认值）
状态：state.json（与本 config 同目录）
日志：config 同目录下 logs/netguard.log 与 logs/shots/ 认证截图
"""

import argparse
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# pythonw 下调用 taskkill/route 等控制台程序会弹黑窗，必须加 CREATE_NO_WINDOW
SUBPROC_FLAGS = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

# Playwright 浏览器内核固定收在工具文件夹内（必须在 import playwright 之前生效）
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(SCRIPT_DIR, "browsers")

# ---------------------------------------------------------------- 默认配置

DEFAULT_CONFIG = {
    # --- 探测 ---
    "probe_interval_sec": 30,          # 探测间隔
    "fail_threshold": 3,               # 连续失败多少次判定断网
    "probe_timeout_sec": 4,            # 单个目标超时
    # 探测目标（IP 直连不走 DNS，任一「真实数据往返」成功即在线）。
    # 443=TLS 握手（第 3 项填 SNI），80=HTTP 请求往返。
    # ⚠️ 必须用中立大站 CDN 的 IP：
    #  1) 部分校园网未认证时会放行 223.5.5.5/114.114.114.114 等检测类 IP（实测有校园网如此），
    #     用它们做探测会永远「在线」——此坑实测踩过，故默认用中立大站 CDN 的 IP；
    #  2) TUN 虚拟网卡会本地假完成 TCP 握手，只有 TLS/HTTP 真实往返才能识破；
    #  3) 纯 IP 直连不怕校园网 DNS 劫持。
    # CDN IP 若长期未变可不管；若失效（在线却总判断网）用 nslookup www.baidu.com 更新。
    "probe_targets": [
        ["153.3.238.28", 443, "www.baidu.com"],
        ["58.217.133.225", 443, "www.qq.com"],
        ["121.226.246.3", 443, "www.jd.com"],
    ],
    "boot_grace_sec": 180,             # 启动宽限期：开机/登录后这段时间内只探测不动作
    "heartbeat_min": 30,               # 在线时每 N 分钟写一条心跳日志，便于确认脚本活着

    # --- 重启保护 ---
    "reboot_cooldown_min": 30,         # 距上次重启不足该分钟数则不再重启
    "max_reboots_per_24h": 3,          # 24 小时内最多重启次数
    "reboot_countdown_sec": 60,        # 重启前弹窗倒计时秒数（人在机器前可取消）
    "cancel_suppress_min": 120,        # 用户取消重启后，多少分钟内不再弹窗/重启
    "auth_before_reboot": True,        # 无任务时先尝试一次自动认证，失败才重启

    # --- 自动认证（校园网） ---
    "auth_retry_min": 5,               # 认证重试基础间隔（分钟），失败后指数退避
    "auth_retry_max_min": 30,          # 退避上限
    "max_auth_per_day": 10,            # 每日自动认证次数上限（防反复提交触发账号锁定）
    # 校园网认证页地址；留空则访问 http://www.msftconnecttest.com/redirect
    # 借助校园网未认证时的 302 劫持自动跳到认证页
    "portal_url": "",
    "campus_account": "",              # 校园网账号
    "campus_password": "",             # 校园网密码
    "username_selector": "",           # 可选：手动指定账号输入框 CSS 选择器
    "password_selector": "",           # 可选：手动指定密码输入框选择器
    "submit_selector": "",             # 可选：手动指定登录按钮选择器
    "headless": True,                  # 认证用无头浏览器（不可见）

    # --- 进程管理 ---
    "task_processes": ["python", "pythonw"],   # 视为「训练任务在跑」的进程名
    # 命令行包含这些子串的 python 进程不算训练任务（如常驻服务）
    "task_ignore_cmdline": ["workbuddy"],
    # 白名单：永不关闭（务必包含你的远控软件！）
    "never_kill": [
        "todesk", "todeskservice", "sunloginclient", "rustdesk", "anydesk",
        "teamviewer", "python", "pythonw",
    ],
    # 断网时关闭的名单（防真实 IP 泄露），按需增删
    "kill_apps": [
        "clash-verge", "verge-mihomo", "verge-mihomo-alpha", "clash-verge-service",
        "clash", "mihomo", "msedge", "chrome", "firefox", "chatgpt", "antigravity",
        "code", "wechat", "weixin", "qq", "dingtalk", "feishu", "telegram",
    ],

    # --- 其他 ---
    "dry_run": True,                   # 演练模式：只记日志，不杀进程/不弹窗/不重启
    "tray_promoted": False,            # 托盘图标位置：false=折叠区(^)，true=任务栏常驻
}

DEFAULT_STATE = {
    "reboots": [],             # 历史重启时间戳（用于 24h 上限）
    "last_reboot_ts": 0.0,
    "last_auth_ts": 0.0,
    "auth_fail_streak": 0,
    "cancel_until_ts": 0.0,    # 用户取消重启后的抑制截止时间
    "last_action_ts": 0.0,     # 断网处理限流
}

# ---------------------------------------------------------------- 工具函数


def normalize_key(name: str) -> str:
    """进程名归一化：去路径、去扩展名、小写、去掉非字母数字（'Clash Verge.exe'与'clash-verge'互相匹配）。"""
    name = os.path.basename((name or "").strip()).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return re.sub(r"[^a-z0-9]", "", name)


def deep_copy_default(d):
    return json.loads(json.dumps(d))


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return deep_copy_default(default)
    except Exception:
        return deep_copy_default(default)


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


_TUN_ROUTE_RE = re.compile(r"^\s*(?:0\.0\.0\.0|128\.0\.0\.0)\s+128\.0\.0\.0\s", re.M)
_CLASH_MARKS = ("clash", "mihomo", "verge")

TRAY_COLORS = {
    "green": (46, 204, 113, 255),    # 在线 · 正式模式
    "yellow": (241, 196, 15, 255),   # 在线 · 演练模式
    "red": (231, 76, 60, 255),       # 断网
}

USERNAME_SELECTORS = [
    'input[name*="user" i]', 'input[id*="user" i]',
    'input[name*="account" i]', 'input[id*="account" i]',
    'input[placeholder*="账号" i]', 'input[placeholder*="帐号" i]',
    'input[placeholder*="用户" i]', 'input[placeholder*="学号" i]',
    'input[placeholder*="工号" i]', 'input[placeholder*="用户名" i]',
    'input[type="text"]', 'input[type="tel"]',
]
SUBMIT_SELECTORS = [
    'button[type="submit"]', 'input[type="submit"]',
    'button:has-text("登录")', 'button:has-text("登 录")',
    'button:has-text("login")', 'a:has-text("登录")',
    'input[value*="登录"]', 'input[type="button"][value*="登录"]',
]

# ---------------------------------------------------------------- 主类


class Guard:
    def __init__(self, config_path: str, skip_grace: bool = False):
        self.skip_grace = skip_grace  # 托盘「重载配置」时跳过长宽限期（网络本来就是通的）
        self.config_path = os.path.abspath(config_path)
        self.data_dir = os.path.dirname(self.config_path)
        self.logs_dir = os.path.join(self.data_dir, "logs")
        self.shots_dir = os.path.join(self.logs_dir, "shots")
        self.state_path = os.path.join(self.data_dir, "state.json")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.shots_dir, exist_ok=True)

        self._setup_logging()

        # 首次运行生成默认配置
        if not os.path.exists(self.config_path):
            save_json(self.config_path, DEFAULT_CONFIG)
            self.log("首次运行：已生成默认配置 %s（请填写校园网账号密码与白名单后重启本脚本）"
                     % self.config_path)
        user_cfg = load_json(self.config_path, {})
        self.cfg = {**DEFAULT_CONFIG, **user_cfg}

        self.state = load_json(self.state_path, DEFAULT_STATE)
        self.start_ts = time.time()
        self.fail_streak = 0

    # ------------------------------------------------ 日志

    def _setup_logging(self):
        import logging
        from logging.handlers import RotatingFileHandler
        self.logger = logging.getLogger("NetGuard")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh = RotatingFileHandler(os.path.join(self.logs_dir, "netguard.log"),
                                 maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        # pythonw 下无控制台，仅在有 stdout 时输出
        try:
            if sys.stdout is not None:
                sh = logging.StreamHandler(sys.stdout)
                sh.setFormatter(fmt)
                self.logger.addHandler(sh)
        except Exception:
            pass

    def log(self, msg):
        self.logger.info(msg)

    def save_state(self):
        save_json(self.state_path, self.state)

    # ------------------------------------------------ 托盘图标

    def _make_tray_img(self, rgb):
        try:
            from PIL import Image, ImageDraw
        except Exception:
            return None
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse([6, 6, 58, 58], fill=rgb)
        d.ellipse([22, 22, 42, 42], outline=(255, 255, 255, 230), width=4)
        return img

    def _wait_taskbar(self, timeout: int = 60) -> bool:
        """等待任务栏窗口就绪。开机早期 Run 键启动时 explorer 可能尚未创建任务栏，
        过早注册托盘图标会静默失败。"""
        try:
            import ctypes
            user32 = ctypes.windll.user32
        except Exception:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if user32.FindWindowW("Shell_TrayWnd", None):
                return True
            time.sleep(1)
        return False

    def _promote_tray_setting(self):
        """Windows 11：按配置设置本图标的 IsPromoted（1=常驻任务栏，0=折叠区）。
        按 sys.executable 精确匹配注册表条目，不会影响其他图标。"""
        try:
            promoted = 1 if self.cfg.get("tray_promoted") else 0
            root = r"HKCU\Control Panel\NotifyIconSettings"
            out = subprocess.run(["reg", "query", root, "/s"], capture_output=True,
                                 timeout=20, creationflags=SUBPROC_FLAGS).stdout or b""
            exe = sys.executable.lower()
            current_key = None
            for line in out.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("HKEY_"):
                    current_key = line
                elif "executablepath" in line.lower() and exe in line.lower():
                    if current_key:
                        subprocess.run(["reg", "add", current_key, "/v", "IsPromoted",
                                        "/t", "REG_DWORD", "/d", str(promoted), "/f"],
                                       capture_output=True, creationflags=SUBPROC_FLAGS)
                        self.log("托盘显示位置: %s" % ("任务栏" if promoted else "折叠区"))
                    break
        except Exception as e:
            self.log("设置托盘位置失败(不影响守护): %r" % e)

    def _setup_tray(self):
        """系统托盘图标：绿=在线·正式，黄=在线·演练(dry_run)，红=断网。失败则无托盘继续运行。
        在独立线程运行：先等任务栏就绪，避免阻塞探测主循环。"""
        self._tray = None
        self._tray_key = None
        self._tray_net = "启动中"
        self._tray_ready = threading.Event()
        try:
            import pystray
            from pystray import Menu, MenuItem as MI
        except Exception as e:
            self.log("托盘组件不可用(%r)，以无托盘模式继续运行" % e)
            return
        if not self._wait_taskbar(60):
            self.log("等待任务栏超时，仍尝试创建托盘图标")
        img = self._make_tray_img(TRAY_COLORS["yellow"])
        if img is None:
            self.log("Pillow 不可用，托盘未启动（守护逻辑不受影响）")
            return

        def status_text(item):
            return "状态：%s · %s" % (
                self._tray_net, "演练模式(dry_run)" if self.cfg["dry_run"] else "正式模式")

        def open_logs(icon, item):
            os.startfile(self.logs_dir)

        def open_config(icon, item):
            try:
                os.startfile(self.config_path)
            except Exception:
                subprocess.Popen(["notepad", self.config_path])

        menu = Menu(
            MI(status_text, None, enabled=False),
            Menu.SEPARATOR,
            MI("打开日志文件夹", open_logs),
            MI("打开配置文件", open_config),
            MI("重载配置并重启", lambda icon, item: self._tray_relaunch()),
            MI("退出", lambda icon, item: self._tray_exit(icon)),
        )
        self._tray = pystray.Icon("NetGuard", img, "NetGuard 启动中…", menu)

        def on_tray_ready(icon):
            icon.visible = True  # ⚠️ 自定义 setup 必须显式显示图标，否则永远不可见
            self._tray_ready.set()

        self._tray.run_detached(setup=on_tray_ready)
        self._promote_tray_setting()
        self.log("托盘图标已启动（绿=在线·正式，黄=在线·演练，红=断网）")

    def _setup_tray_async(self):
        threading.Thread(target=self._setup_tray, daemon=True, name="tray-setup").start()

    def _update_tray(self, online: bool):
        self._tray_net = "在线" if online else "断网"
        if not self._tray:
            return
        key = (online, bool(self.cfg["dry_run"]))
        if key == self._tray_key:
            return
        self._tray_key = key
        try:
            # 等托盘线程完成初始化，避免竞态导致首次变色丢失
            if not self._tray_ready.wait(5):
                self.log("托盘线程 5 秒未就绪，跳过本次图标更新")
                return
            if not online:
                rgb, tip = TRAY_COLORS["red"], "NetGuard：断网，处理中"
            elif self.cfg["dry_run"]:
                rgb, tip = TRAY_COLORS["yellow"], "NetGuard：在线（演练模式 dry_run）"
            else:
                rgb, tip = TRAY_COLORS["green"], "NetGuard：在线"
            img = self._make_tray_img(rgb)
            if img is not None:
                self._tray.icon = img
            self._tray.title = tip
        except Exception as e:
            self.log("托盘图标更新失败: %r" % e)

    def _tray_relaunch(self):
        self.log("托盘操作：重载配置并重启进程")
        try:
            self._tray.visible = False  # 先注销托盘图标，避免残留幽灵图标
        except Exception:
            pass
        try:
            subprocess.Popen([sys.executable, os.path.abspath(__file__), "--skip-grace"])
        except Exception as e:
            self.log("重启失败: %r" % e)
            return
        time.sleep(0.8)
        os._exit(0)

    def _tray_exit(self, icon):
        self.log("托盘操作：用户请求退出")
        try:
            icon.visible = False  # 注销托盘图标
        except Exception:
            pass
        os._exit(0)

    # ------------------------------------------------ 探测

    def _probe_deep(self, host, port, timeout, sni=None):
        """真实数据往返探测：443=TLS 握手，其他端口=HTTP 请求往返。
        TUN 网卡会在本地假完成 TCP 握手，但真实数据往返骗不了，上游断了必然失败。"""
        try:
            with socket.create_connection((host, int(port)), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if int(port) == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE  # 只验证连通性，不校验证书
                    with ctx.wrap_socket(sock, server_hostname=sni or host):
                        return True
                sock.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
                return sock.recv(64).startswith(b"HTTP/")
        except OSError:
            return False

    def probe_all(self) -> bool:
        """任一目标完成真实数据往返即视为在线。"""
        timeout = float(self.cfg["probe_timeout_sec"])
        for item in self.cfg["probe_targets"]:
            if self._probe_deep(item[0], item[1], timeout, item[2] if len(item) > 2 else None):
                return True
        return False

    def tun_routes_present(self):
        """TUN 全局接管常用 0.0.0.0/1 + 128.0.0.0/1 两条路由；仅用于日志判断疑似原因。"""
        try:
            # 中文 Windows 下 route 输出为 GBK，按字节读取再忽略错误解码（路由行均为 ASCII 数字）
            raw = subprocess.run(["route", "print", "-4"], capture_output=True,
                                 timeout=15, creationflags=SUBPROC_FLAGS).stdout or b""
            out = raw.decode("utf-8", errors="ignore")
            return bool(_TUN_ROUTE_RE.search(out))
        except Exception:
            return None

    def clash_running(self) -> bool:
        try:
            import psutil
            for p in psutil.process_iter(["name"]):
                n = (p.info["name"] or "").lower()
                if any(m in n for m in _CLASH_MARKS):
                    return True
        except Exception:
            pass
        return False

    # ------------------------------------------------ 进程管理

    def find_task_processes(self):
        """返回训练任务进程列表（排除本脚本自身/其他守护实例/命令行命中忽略名单的常驻服务）。"""
        import psutil
        me = os.getpid()
        wanted = {normalize_key(n) for n in self.cfg["task_processes"]}
        ignore = [s.lower() for s in self.cfg.get("task_ignore_cmdline", [])]
        found = []
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = normalize_key(p.info["name"] or "")
                if name not in wanted or p.info["pid"] == me:
                    continue
                cmd = " ".join(p.info["cmdline"] or []).lower()
                if "net_guard" in cmd:  # 守护脚本自己的 python 进程不算任务
                    continue
                if any(s in cmd for s in ignore):  # 常驻服务不算任务
                    continue
                found.append({"pid": p.info["pid"], "name": p.info["name"], "cmd": cmd[:120]})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return found

    def kill_apps(self):
        """关闭 kill_apps 名单内进程（温和关闭 → 8s 后强杀），绝不碰白名单与自身。"""
        import psutil
        never = {normalize_key(n) for n in self.cfg["never_kill"]}
        kill = {normalize_key(n) for n in self.cfg["kill_apps"]} - never
        me = os.getpid()
        targets = []
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = normalize_key(p.info["name"] or "")
                if name not in kill or p.info["pid"] == me:
                    continue
                cmd = " ".join(p.info["cmdline"] or []).lower()
                if "net_guard" in cmd:
                    continue
                targets.append((p.info["pid"], p.info["name"]))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        names = sorted({n for _, n in targets})
        if not names:
            self.log("未发现需要关闭的名单进程")
            return
        if self.cfg["dry_run"]:
            self.log("[DRY-RUN] 将关闭进程（实际未执行）: %s" % ", ".join(names))
            return

        for pid, _ in targets:  # 温和：请求关闭窗口
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True,
                           creationflags=SUBPROC_FLAGS)
        time.sleep(8)
        for pid, _ in targets:  # 兜底强杀（对已退出进程报错无害）
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True,
                           creationflags=SUBPROC_FLAGS)
        self.log("已关闭名单进程: %s" % ", ".join(names))

    # ------------------------------------------------ 自动认证（Playwright）

    def _first_visible(self, page, selectors):
        for sel in selectors:
            try:
                loc = page.locator(sel)
                for i in range(loc.count()):
                    el = loc.nth(i)
                    try:
                        if el.is_visible():
                            return el
                    except Exception:
                        continue
            except Exception:
                continue
        return None

    def _goto_with_retry(self, page, url, attempts: int = 2):
        """打开页面，失败短暂重试一次（对抗安全软件/代理的间歇性拦截）。"""
        last = None
        for i in range(attempts):
            try:
                page.goto(url, timeout=25000)
                return
            except Exception as e:
                last = e
                if i + 1 < attempts:
                    self.log("打开页面失败，2 秒后重试: %s" % str(e)[:90])
                    page.wait_for_timeout(2000)
        raise last

    def _save_shot(self, page, tag):
        try:
            fn = os.path.join(self.shots_dir,
                              time.strftime("%Y%m%d-%H%M%S") + "-" + tag + ".png")
            page.screenshot(path=fn)
            self.log("已保存认证截图: %s" % fn)
            shots = sorted(f for f in os.listdir(self.shots_dir) if f.endswith(".png"))
            for f in shots[:-20]:
                try:
                    os.remove(os.path.join(self.shots_dir, f))
                except OSError:
                    pass
        except Exception as e:
            self.log("截图失败: %r" % e)

    def _auth_daily_left(self) -> bool:
        today = time.strftime("%Y-%m-%d")
        if self.state.get("auth_date") != today:
            self.state["auth_date"] = today
            self.state["auth_count_today"] = 0
        return int(self.state.get("auth_count_today", 0)) < int(self.cfg.get("max_auth_per_day", 10))

    def attempt_auth(self) -> bool:
        """打开校园网认证页 → 填账号密码 → 提交 → 以连通性探测结果为准。"""
        self.state["last_auth_ts"] = time.time()
        self.save_state()

        account = self.cfg.get("campus_account") or ""
        password = self.cfg.get("campus_password") or ""
        if not account or not password:
            self.log("config.json 未填写 campus_account/campus_password，跳过自动认证")
            return False
        if not self._auth_daily_left():
            self.log("今日自动认证次数已达上限 %d，跳过（防止触发账号锁定）"
                     % int(self.cfg.get("max_auth_per_day", 10)))
            return False
        self.state["auth_count_today"] = int(self.state.get("auth_count_today", 0)) + 1
        self.save_state()
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self.log("playwright 导入失败，无法自动认证（请检查 env/browsers 目录）: %r" % e)
            return False

        url = self.cfg.get("portal_url") or "http://www.msftconnecttest.com/redirect"
        self.log("开始自动认证: %s" % url)
        ok = False
        try:
            with sync_playwright() as pw:
                # 优先用内置 Chromium（版本固定、行为确定）；个别环境它不可用时退回系统 Edge。
                # --no-proxy-server：认证页必须直连（校园网内网页）；同时规避
                # 「Clash 被杀后系统代理残留指向死端口」与「代理 REJECT 规则拦截认证页」两类问题。
                launch_args = ["--disable-blink-features=AutomationControlled",
                               "--no-proxy-server"]
                try:
                    browser = pw.chromium.launch(headless=bool(self.cfg.get("headless", True)),
                                                 args=launch_args)
                    self.log("认证浏览器: 内置 Chromium")
                except Exception:
                    browser = pw.chromium.launch(headless=bool(self.cfg.get("headless", True)),
                                                 channel="msedge", args=launch_args)
                    self.log("认证浏览器: 系统 Edge")
                page = browser.new_page(ignore_https_errors=True)
                # 抹掉 navigator.webdriver 自动化特征
                page.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
                self._goto_with_retry(page, url)
                page.wait_for_timeout(2500)
                if not self.cfg.get("portal_url"):
                    page.wait_for_timeout(2500)  # 等校园网 302 劫持跳转
                self._save_shot(page, "1-before")

                pass_sel = self.cfg.get("password_selector") or 'input[type="password"]'
                pwd = page.locator(pass_sel).first
                pwd.wait_for(state="visible", timeout=15000)

                user_sel = self.cfg.get("username_selector")
                user_el = (page.locator(user_sel).first if user_sel
                           else self._first_visible(page, USERNAME_SELECTORS))
                if user_el is None:
                    raise RuntimeError("未找到账号输入框（可在 config.json 配置 username_selector）")

                # 逐字输入 + 随机停顿：兼容按键监听的表单，行为也更接近真人
                page.wait_for_timeout(random.randint(300, 800))
                user_el.click()
                try:
                    user_el.press_sequentially(account, delay=random.randint(40, 80))
                except Exception:
                    user_el.fill(account)
                page.wait_for_timeout(random.randint(200, 500))
                pwd.click()
                try:
                    pwd.press_sequentially(password, delay=random.randint(40, 80))
                except Exception:
                    pwd.fill(password)
                page.wait_for_timeout(random.randint(200, 500))

                clicked = False
                submit_sel = self.cfg.get("submit_selector")
                if submit_sel:
                    try:
                        page.locator(submit_sel).first.click(timeout=3000)
                        clicked = True
                    except Exception:
                        pass
                if not clicked:
                    btn = self._first_visible(page, SUBMIT_SELECTORS)
                    if btn is not None:
                        btn.click()
                        clicked = True
                if not clicked:
                    pwd.press("Enter")

                page.wait_for_timeout(8000)
                self._save_shot(page, "2-after")
                browser.close()
            ok = self.probe_all()
        except Exception as e:
            self.log("自动认证流程异常: %r" % e)
            ok = self.probe_all()

        self.log("自动认证结果: %s" % ("成功，网络已恢复" if ok else "未成功（按退避间隔重试）"))
        return ok

    def auth_interval_min(self) -> int:
        base = int(self.cfg["auth_retry_min"])
        mx = int(self.cfg["auth_retry_max_min"])
        streak = int(self.state.get("auth_fail_streak", 0))
        return min(mx, base * (2 ** min(streak, 3)))

    def should_try_auth(self, now: float) -> bool:
        return now - float(self.state.get("last_auth_ts", 0.0)) >= self.auth_interval_min() * 60

    def _record_auth_result(self, ok: bool):
        if ok:
            self.state["auth_fail_streak"] = 0
        else:
            self.state["auth_fail_streak"] = int(self.state.get("auth_fail_streak", 0)) + 1
        self.save_state()

    # ------------------------------------------------ 通用化工具命令

    def refresh_probe_targets(self):
        """联网状态下解析公共 CDN 当前 IP 并写回 config.json。
        用于首次部署/更换网络环境/CDN 变更后刷新探测目标。"""
        targets = []
        for host in ("www.baidu.com", "www.qq.com", "www.jd.com"):
            try:
                ip = socket.gethostbyname(host)
                targets.append([ip, 443, host])
                print("%s -> %s" % (host, ip))
            except OSError as e:
                print("%s 解析失败: %r" % (host, e))
        if len(targets) < 2:
            print("可用目标不足 2 个，放弃写回（请确认当前已联网）")
            return
        self.cfg["probe_targets"] = targets
        merged = load_json(self.config_path, {})
        merged["probe_targets"] = targets
        save_json(self.config_path, merged)
        print("已写回 %s 的 probe_targets" % self.config_path)

    def dump_auth_page(self):
        """打印认证页表单结构（输入框/按钮/可见性），辅助配置自定义选择器；保存截图。"""
        url = self.cfg.get("portal_url") or "http://www.msftconnecttest.com/redirect"
        print("打开页面: %s" % url)
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            print("playwright 不可用: %r" % e)
            return
        try:
            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(
                        headless=True,
                        args=["--disable-blink-features=AutomationControlled",
                              "--no-proxy-server"])
                except Exception:
                    browser = pw.chromium.launch(headless=True, channel="msedge",
                                                 args=["--no-proxy-server"])
                page = browser.new_page(ignore_https_errors=True)
                self._goto_with_retry(page, url)
                page.wait_for_timeout(3000)
                print("最终 URL: %s" % page.url)
                print("标题: %s" % page.title())
                print("--- 输入框 ---")
                for el in page.locator("input").all():
                    try:
                        print("type=%s name=%s id=%s placeholder=%s visible=%s" % (
                            el.get_attribute("type"), el.get_attribute("name"),
                            el.get_attribute("id"), el.get_attribute("placeholder"),
                            el.is_visible()))
                    except Exception:
                        continue
                print("--- 按钮 ---")
                for el in page.locator("button").all():
                    try:
                        print("button text=%r visible=%s" % (
                            (el.inner_text() or "").strip()[:24], el.is_visible()))
                    except Exception:
                        continue
                self._save_shot(page, "dump")
                browser.close()
                print("截图已保存到 logs/shots/（文件名含 dump）")
        except Exception as e:
            print("页面打开失败: %r" % e)

    def test_auth(self):
        """手动测试一次自动认证：不杀进程、不重启，结果以连通性为准。
        已登录状态下无密码框可用，会以「网络可达」告终，属正常。"""
        print("模式: dry_run=%s（本命令不会杀进程/重启）" % self.cfg.get("dry_run"))
        ok = self.attempt_auth()
        print("测试结果: %s" % ("通过（网络可达）" if ok else "未通过（看日志与 logs/shots/ 截图排查）"))

    # ------------------------------------------------ 重启

    def can_reboot(self, now: float):
        if now - float(self.state.get("last_reboot_ts", 0.0)) < int(self.cfg["reboot_cooldown_min"]) * 60:
            return False, "处于 %d 分钟重启冷却期" % int(self.cfg["reboot_cooldown_min"])
        cutoff = now - 24 * 3600
        recent = [t for t in self.state.get("reboots", []) if t > cutoff]
        if len(recent) >= int(self.cfg["max_reboots_per_24h"]):
            return False, "24 小时内重启已达上限 %d 次" % int(self.cfg["max_reboots_per_24h"])
        return True, ""

    def reboot_countdown(self, seconds: int) -> bool:
        """弹置顶倒计时窗口：人在电脑前可取消；锁屏/无人时窗口不可见，倒计时走完返回 True。"""
        try:
            import tkinter as tk
        except Exception as e:
            self.log("tkinter 不可用(%r)，按无人值守直接重启" % e)
            return True
        result = {"cancel": False}
        try:
            root = tk.Tk()
            root.title("NetGuard 断网自动重启")
            root.attributes("-topmost", True)
            root.geometry("460x170+280+220")
            root.protocol("WM_DELETE_WINDOW",
                          lambda: (result.__setitem__("cancel", True), root.destroy()))
            left = {"t": int(seconds)}
            lbl = tk.Label(root, text="", font=("Microsoft YaHei", 12), justify="center")
            lbl.pack(expand=True, fill="both", padx=16, pady=(18, 6))

            def tick():
                if left["t"] <= 0:
                    try:
                        root.destroy()
                    except Exception:
                        pass
                    return
                lbl.config(text="检测到断网且自动认证未能恢复网络。\n"
                                "将于 %d 秒后重启电脑；人在电脑前可点击下方按钮取消。" % left["t"])
                left["t"] -= 1
                root.after(1000, tick)

            tk.Button(root, text="取消重启", font=("Microsoft YaHei", 11), width=12, height=1,
                      command=lambda: (result.__setitem__("cancel", True), root.destroy())
                      ).pack(pady=(0, 14))
            tick()
            root.mainloop()
        except Exception as e:
            self.log("弹窗失败(%r)，按无人值守直接重启" % e)
            return True
        return not result["cancel"]

    def do_reboot(self):
        now = time.time()
        self.state.setdefault("reboots", []).append(now)
        self.state["last_reboot_ts"] = now
        self.save_state()  # 必须在关机前落盘
        self.log("执行重启: shutdown /r /t 5 /f（5 秒内可用 shutdown /a 中止）")
        subprocess.run(["shutdown", "/r", "/t", "5", "/f",
                        "/c", "NetGuard: sustained offline, auto reboot"],
                       capture_output=True, creationflags=SUBPROC_FLAGS)

    # ------------------------------------------------ 断网处理

    def handle_offline(self):
        now = time.time()
        grace = 15 if self.skip_grace else int(self.cfg["boot_grace_sec"])
        if now - self.start_ts < grace:
            self.log("处于启动宽限期（剩余 %d 秒），仅探测不动作"
                     % int(grace - (now - self.start_ts)))
            return
        if now - float(self.state.get("last_action_ts", 0.0)) < 60:
            return  # 断网处理限流：最快每 60s 一轮
        self.state["last_action_ts"] = now
        self.save_state()

        if now < float(self.state.get("cancel_until_ts", 0.0)):
            self.log("处于用户取消后的抑制期（至 %s），仅监控不动作"
                     % time.strftime("%H:%M", time.localtime(self.state["cancel_until_ts"])))
            return

        # 疑似原因（仅记录日志，不影响动作）
        marks = []
        tun = self.tun_routes_present()
        if tun:
            marks.append("存在 TUN 全局路由")
        if self.clash_running():
            marks.append("Clash 进程在运行")
        self.log("疑似断网原因: %s（仅推测）"
                 % ("、".join(marks) if marks else "未检测到 TUN/Clash 特征，可能为校园网认证或线路问题"))

        tasks = self.find_task_processes()
        if tasks:
            self.log("检测到训练任务进程: %s → 本次不重启"
                     % ", ".join("%s(PID %d)" % (t["name"], t["pid"]) for t in tasks))
            self.kill_apps()
            if self.should_try_auth(now):
                self._record_auth_result(self.attempt_auth())
            return

        # 无训练任务
        self.kill_apps()
        if self.cfg.get("auth_before_reboot", True) and self.should_try_auth(now):
            if self.attempt_auth():
                self._record_auth_result(True)
                self.log("自动认证成功，网络恢复，无需重启")
                return
            self._record_auth_result(False)

        ok, reason = self.can_reboot(now)
        if not ok:
            self.log("暂不重启: %s" % reason)
            return

        self.log("自动认证不可用/失败，准备重启计算机")
        if self.cfg["dry_run"]:
            self.log("[DRY-RUN] 跳过重启确认弹窗与重启")
            return
        if self.reboot_countdown(int(self.cfg["reboot_countdown_sec"])):
            self.do_reboot()
        else:
            self.state["cancel_until_ts"] = time.time() + int(self.cfg["cancel_suppress_min"]) * 60
            self.save_state()
            self.log("用户取消重启，%d 分钟内不再弹窗/重启" % int(self.cfg["cancel_suppress_min"]))

    # ------------------------------------------------ 单实例

    def check_single_instance(self) -> bool:
        import psutil
        me = os.getpid()
        other = None
        for attempt in range(2):  # 重试一次：给托盘「重载配置」新旧实例交接留时间
            other = None
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                if p.info["pid"] == me:
                    continue
                name = (p.info["name"] or "").lower()
                if not name.startswith("python"):
                    continue
                cmd = " ".join(p.info["cmdline"] or []).lower()
                if "net_guard.py" in cmd:
                    other = p.info["pid"]
                    break
            if other is None:
                return True
            if attempt == 0:
                self.log("发现已有 NetGuard 实例(PID %d)，3 秒后复查（可能是重启交接）" % other)
                time.sleep(3)
        self.log("已有 NetGuard 实例(PID %d)在运行，本实例退出" % other)
        return False

    # ------------------------------------------------ 主循环

    def run(self):
        try:
            import psutil  # noqa: F401  核心依赖，提前校验
        except Exception as e:
            self.log("缺少 psutil（%r），请先运行 install.bat 安装依赖" % e)
            return

        self.log("=" * 60)
        self.log("NetGuard 启动 | dry_run=%s | 探测间隔 %ds x 连续 %d 次判定断网 | "
                 "portal_url=%s | 账号%s"
                 % (self.cfg["dry_run"], self.cfg["probe_interval_sec"],
                    self.cfg["fail_threshold"],
                    "已配置" if self.cfg.get("portal_url") else "未配置(用302劫持)",
                    "已配置" if self.cfg.get("campus_account") else "未配置"))
        if not self.check_single_instance():
            return
        self._setup_tray_async()
        last_beat = time.time()

        while True:
            try:
                if self.probe_all():
                    self._update_tray(True)
                    if time.time() - last_beat >= int(self.cfg["heartbeat_min"]) * 60:
                        last_beat = time.time()
                        self.log("心跳：在线（dry_run=%s）" % self.cfg["dry_run"])
                    if self.fail_streak >= int(self.cfg["fail_threshold"]):
                        self.log("网络已恢复")
                    self.fail_streak = 0
                    if self.state.get("cancel_until_ts") or self.state.get("auth_fail_streak"):
                        self.state["cancel_until_ts"] = 0.0
                        self.state["auth_fail_streak"] = 0
                        self.save_state()
                else:
                    self._update_tray(False)
                    self.fail_streak += 1
                    self.log("网络探测失败（连续 %d/%d 次）"
                             % (self.fail_streak, int(self.cfg["fail_threshold"])))
                    if self.fail_streak >= int(self.cfg["fail_threshold"]):
                        self.handle_offline()
            except Exception:
                import logging
                self.logger.exception("主循环异常")
            time.sleep(int(self.cfg["probe_interval_sec"]))


def main():
    ap = argparse.ArgumentParser(description="NetGuard 断网守护脚本")
    ap.add_argument("--config", default=os.path.join(SCRIPT_DIR, "config.json"),
                    help="配置文件路径（state/log 等运行时文件放在其同目录）")
    ap.add_argument("--skip-grace", action="store_true",
                    help="跳过启动宽限期（托盘「重载配置」时使用，此时网络本就通畅）")
    ap.add_argument("--refresh-probe", action="store_true",
                    help="联网状态下刷新探测目标 CDN IP 并写回 config.json")
    ap.add_argument("--test-auth", action="store_true",
                    help="手动测试一次校园网自动认证（不杀进程/不重启）")
    ap.add_argument("--dump-page", action="store_true",
                    help="打印认证页表单结构与截图，辅助配置自定义选择器")
    args = ap.parse_args()
    guard = Guard(args.config, skip_grace=args.skip_grace)
    if args.refresh_probe:
        guard.refresh_probe_targets()
    elif args.dump_page:
        guard.dump_auth_page()
    elif args.test_auth:
        guard.test_auth()
    else:
        guard.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
