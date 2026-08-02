#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import smtplib
import email.utils
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText

import requests

# ============ 配置 ============

# 配置文件路径（与脚本同目录）
CONFIG_DIR = Path(__file__).parent
CONFIG_FILE = CONFIG_DIR / "sijishe_config.json"
LOG_FILE = CONFIG_DIR / "sijishe_sign.log"

# 日志级别
LOG_LEVELS = {"DEBUG": 0, "INFO": 1, "OK": 2, "WARN": 3, "ERROR": 4}
LOG_LEVEL_ICONS = {"DEBUG": "🔍", "INFO": "ℹ️", "OK": "✅", "WARN": "⚠️", "ERROR": "❌"}

# 签到页面路径
SIGN_PAGE = "/k_misign-sign.html"
SIGN_API = "/plugin.php"
MAGIC_PAGE = "/home.php"

# ============ 域名管理（基于配置文件）============

# 优选域名有效期（秒）：7 天
PREFERRED_DOMAIN_TTL = 7 * 24 * 3600


def load_domains_from_config():
    """加载域名列表:env 模式来自 SJS_DOMAINS;本地模式来自配置文件。无配置则返回空列表"""
    cfg = load_config()
    cfg = ensure_config(cfg)
    return cfg.get("domains", [])


def save_domains_to_config(domains):
    """将域名列表写入配置文件"""
    cfg = load_config()
    cfg = ensure_config(cfg)
    cfg["domains"] = domains
    save_config(cfg)
    log(f"域名列表已更新: {len(domains)} 个域名", "DEBUG")


# 域名自动探寻来源:论坛首页中提取的镜像域名关键词模式
DOMAIN_HINT_PATTERNS = [
    # 形如 "地址: example.net" 或 "备用: xxx.com"
    r'(?:地址|域名|备用|入口|镜像)\s*[:：]\s*([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})',
    # 形如 https://example.net 的链接
    r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})',
]
# 域名自动探寻时排除的干扰项(图片 CDN、非论坛站点等)
DOMAIN_HINT_BLACKLIST = {
    "urlimage.cc", "comsenz.com", "t.me", "47447.net",
    "www.comsenz.com", "xsijishe.com",
}


def _looks_like_forum(domain):
    """访问域名首页，检查是否具备 Discuz 论坛特征（用于过滤外链/非论坛域名）"""
    try:
        resp = requests.get(
            f"https://{domain}/",
            timeout=8, allow_redirects=True,
            headers={"User-Agent": get_common_headers()["User-Agent"]},
        )
        if resp.status_code != 200:
            return False
        low = resp.text.lower()
        return any(m in low for m in ("formhash", "k_misign", "forum.php", "discuz"))
    except requests.RequestException:
        return False


def discover_domains(seed_domains=None):
    """
    自动探寻可用的镜像分流域名
    策略:
      1. 以 seed_domains（通常来自 GitHub Variables）为种子
      2. 抓取任一可达论坛首页，提取镜像域名线索，与种子合并去重
      3. 延迟探测，仅保留可访问的域名，更新配置文件
    返回最终的域名列表
    """
    seed = [d.strip() for d in (seed_domains or []) if d.strip()]
    if not seed:
        seed = load_domains_from_config()
    if not seed:
        log("域名自动探寻: 未配置种子域名 (SJS_DOMAINS)，无法探寻", "ERROR")
        return []

    # 1) 抓取种子域名首页，收集镜像域名线索
    hints = set(seed)
    fetched = False
    for domain in seed:
        try:
            resp = requests.get(
                f"https://{domain}/",
                timeout=8, allow_redirects=True,
                headers={"User-Agent": get_common_headers()["User-Agent"]},
            )
            if resp.status_code != 200:
                continue
            fetched = True
            for pat in DOMAIN_HINT_PATTERNS:
                for m in re.finditer(pat, resp.text):
                    cand = m.group(1).strip().lower().rstrip("/")
                    # 去掉可能带路径的部分（如 urlimage.cc/attachments/...）
                    if "/" in cand:
                        cand = cand.split("/")[0]
                    if re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", cand) \
                            and cand not in DOMAIN_HINT_BLACKLIST:
                        hints.add(cand)
            break  # 抓到一个可用首页即可
        except requests.RequestException:
            continue
    if not fetched:
        log("域名自动探寻: 种子域名均不可达，保留原列表", "WARN")
        return seed

    # 2) 延迟探测 + 论坛特征验证，仅保留可访问且像论坛的域名
    #    种子域名信任原列表；新探寻到的域名需具备 Discuz 特征，避免混入外链
    live = []
    for domain in sorted(hints):
        _, status = test_latency(domain, timeout=4)
        if not (status and status < 500):
            continue
        if domain in seed or _looks_like_forum(domain):
            live.append(domain)
    if not live:
        log("域名自动探寻: 探测后无可用域名，保留种子列表", "WARN")
        return seed

    # 3) 更新配置
    log(f"域名自动探寻: 发现 {len(hints)} 个候选，可用 {len(live)} 个", "OK")
    save_domains_to_config(live)
    return live


# ============ 签到状态缓存 ============

# 签到状态常量
SIGN_STATE_NONE = "none"            # 未执行过签到
SIGN_STATE_SIGNED = "signed"        # 今日签到成功
SIGN_STATE_MAKEUP = "makeup"        # 执行了补签
SIGN_STATE_ALREADY = "already"      # 今日已签到（非本次操作）
SIGN_STATE_FAILED = "failed"        # 签到失败


def load_last_sign_state():
    """读取上次签到状态缓存"""
    cfg = load_config()
    cfg = ensure_config(cfg)
    return cfg.get("last_sign", {})


def save_last_sign_state(state: str):
    """写入本次签到状态缓存"""
    from datetime import date
    cfg = load_config()
    cfg = ensure_config(cfg)
    cfg["last_sign"] = {
        "state": state,
        "date": str(date.today()),
    }
    save_config(cfg)


def get_preferred_domain():
    """获取有效的优选域名，过期返回 None"""
    cfg = load_config()
    cfg = ensure_config(cfg)
    domain = cfg.get("preferred_domain", "")
    ts = cfg.get("preferred_domain_ts", 0)
    if domain and ts and (time.time() - ts) < PREFERRED_DOMAIN_TTL:
        return domain
    return None


def set_preferred_domain(domain):
    """将优选域名写入配置文件，记录时间戳"""
    cfg = load_config()
    cfg = ensure_config(cfg)
    cfg["preferred_domain"] = domain
    cfg["preferred_domain_ts"] = time.time()
    save_config(cfg)
    log(f"优选域名已记录: {domain}", "DEBUG")


# 邮件默认配置（可被配置文件覆盖）
DEFAULT_MAIL_CONFIG = {
    "smtp_host": "smtp.qq.com",
    "smtp_port": 465,
    "smtp_ssl": True,
    "sender": "",
    "password": "",
    "receivers": [],
}

# ============ 日志模块 ============


def log(msg, level="INFO", end="\n"):
    """统一日志输出：GitHub Actions 环境变量模式仅输出控制台；本地模式同时写文件"""
    icon = LOG_LEVEL_ICONS.get(level, "")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {icon} {msg}"

    # 控制台输出
    print(f"{icon} {msg}", end=end)

    # 文件输出（带完整时间戳）——env 模式下不落盘，仅随 Actions 控制台输出
    if is_env_mode():
        return
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def log_separator(title=None):
    """输出分隔线"""
    if title:
        sep = f"\n{'=' * 55}\n  {title}\n{'=' * 55}"
    else:
        sep = "-" * 55
    print(sep)
    if is_env_mode():
        return
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(sep + "\n")
    except OSError:
        pass


# ============ 配置管理 ============

# GitHub Actions Secrets / Variables 环境变量前缀
ENV_PREFIX = "SJS_"


def is_env_mode():
    """是否运行在 GitHub Actions 环境变量配置模式(检测到 SJS_* 环境变量)"""
    return any(k.startswith(ENV_PREFIX) for k in os.environ)


def load_config_from_env():
    """从 GitHub Actions Secrets / Variables 环境变量构建配置(内存,不落盘)"""
    def _env(name, default=""):
        return os.environ.get(ENV_PREFIX + name, default)

    return {
        "cookie": _env("COOKIE"),
        "account": {
            "username": _env("USERNAME"),
            "password": _env("PASSWORD"),
        },
        "email": {
            "smtp_host": _env("SMTP_HOST", "smtp.qq.com"),
            "smtp_port": int(_env("SMTP_PORT", "465") or 465),
            "smtp_ssl": _env("SMTP_SSL", "true").lower() in ("true", "1", "yes"),
            "sender": _env("SMTP_SENDER"),
            "password": _env("SMTP_PASSWORD"),
            "receivers": [r.strip() for r in _env("SMTP_RECEIVERS").split(",") if r.strip()],
        },
        "domains": [d.strip() for d in _env("DOMAINS").split(",") if d.strip()],
        "preferred_domain": "",
        "preferred_domain_ts": 0,
        "last_sign": {"state": SIGN_STATE_NONE, "date": ""},
    }


def load_config():
    """加载配置:环境变量模式(GitHub Actions)直接由 env 构建;否则读本地文件"""
    if is_env_mode():
        return load_config_from_env()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            log("配置文件损坏，使用默认配置", "WARN")
    return {"cookie": "", "email": dict(DEFAULT_MAIL_CONFIG)}


def save_config(cfg):
    """保存配置:环境变量模式下不落盘(GitHub Actions 每次运行全新环境)"""
    if is_env_mode():
        return
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
    log("配置已保存", "OK")


def ensure_config(cfg):
    """确保配置文件包含所有必需字段"""
    changed = False
    if "cookie" not in cfg:
        cfg["cookie"] = ""
        changed = True
    if "email" not in cfg:
        cfg["email"] = dict(DEFAULT_MAIL_CONFIG)
        changed = True
    else:
        for k, v in DEFAULT_MAIL_CONFIG.items():
            if k not in cfg["email"]:
                cfg["email"][k] = v
                changed = True
    if "domains" not in cfg:
        cfg["domains"] = []
        changed = True
    if "preferred_domain" not in cfg:
        cfg["preferred_domain"] = ""
        changed = True
    if "account" not in cfg:
        cfg["account"] = {"username": "", "password": ""}
        changed = True
    if changed:
        save_config(cfg)
    return cfg


def read_multiline(prompt="请输入（多行输入，空行结束）:"):
    """读取多行输入，直到空行或 EOF"""
    print(prompt)
    print("  (直接按 Enter 跳过)")
    print("-" * 50)
    lines = []
    try:
        while True:
            line = input()
            # 首次输入即为空 → 直接跳过
            if line.strip() == "" and not lines:
                return ""
            # 后续输入遇到空行 → 结束
            if line.strip() == "" and lines:
                break
            lines.append(line)
    except EOFError:
        pass
    return " ".join(lines).strip()


def update_cookie_interactive(cfg):
    """交互式更新 Cookie"""
    log("请输入 Cookie (登录论坛后，从浏览器开发者工具复制):", "INFO")
    log("  提示: F12 -> 应用/Application -> Cookies -> 复制完整 Cookie 字符串", "INFO")
    cookie_str = read_multiline()
    if not cookie_str:
        log("Cookie 不能为空！", "ERROR")
        return False
    cfg["cookie"] = cookie_str
    save_config(cfg)
    log("Cookie 已保存", "OK")
    return True


def delete_cookie(cfg):
    """删除 Cookie"""
    if not cfg.get("cookie"):
        log("当前没有保存的 Cookie", "WARN")
        return False
    cfg["cookie"] = ""
    save_config(cfg)
    log("Cookie 已删除", "OK")
    return True


def verify_saved_cookie(cfg):
    """验证已保存的 Cookie 是否有效"""
    cookie_str = cfg.get("cookie", "")
    if not cookie_str:
        log("未找到已保存的 Cookie，请先添加", "WARN")
        return False

    cookies = parse_cookie(cookie_str)
    has_auth = any("auth" in k for k in cookies)
    has_saltkey = any("saltkey" in k for k in cookies)
    log(f"Cookie 字段: auth={has_auth}, saltkey={has_saltkey}", "DEBUG")

    if not has_auth or not has_saltkey:
        log("Cookie 缺少关键字段 (auth/saltkey)，可能已失效", "WARN")

    log("正在测试域名延迟...", "INFO")
    domain = pick_fastest_domain()
    if not domain:
        return False

    log(f"正在验证 Cookie (域名: {domain})...", "INFO")
    valid, info = verify_cookie(domain, cookies)
    if valid:
        log(f"Cookie 有效 (用户: {info})", "OK")
        return True
    else:
        log(f"Cookie 无效: {info}", "ERROR")
        return False


def update_email_interactive(cfg):
    """交互式更新邮件配置"""
    log("请输入邮件配置（留空跳过）：", "INFO")
    smtp_host = input(f"  SMTP 服务器 [{cfg['email']['smtp_host']}]: ").strip()
    if smtp_host:
        cfg["email"]["smtp_host"] = smtp_host

    port_str = input(f"  SMTP 端口 [{cfg['email']['smtp_port']}]: ").strip()
    if port_str:
        cfg["email"]["smtp_port"] = int(port_str)

    ssl_str = input(f"  SSL (yes/no) [{'yes' if cfg['email']['smtp_ssl'] else 'no'}]: ").strip().lower()
    if ssl_str in ("yes", "y"):
        cfg["email"]["smtp_ssl"] = True
    elif ssl_str in ("no", "n"):
        cfg["email"]["smtp_ssl"] = False

    sender = input(f"  发件邮箱 [{cfg['email']['sender']}]: ").strip()
    if sender:
        cfg["email"]["sender"] = sender

    pwd_mask = cfg['email']['password'][:4] + "****" if cfg['email']['password'] else ""
    pwd = input(f"  SMTP 授权码 [{pwd_mask}]: ").strip()
    if pwd:
        cfg["email"]["password"] = pwd

    recv_str = input(f"  收件邮箱 (多个用逗号分隔) [{','.join(cfg['email']['receivers'])}]: ").strip()
    if recv_str:
        cfg["email"]["receivers"] = [r.strip() for r in recv_str.split(",")]

    save_config(cfg)
    log("邮件配置已保存", "OK")
    return True


def delete_email(cfg):
    """删除邮件配置"""
    if not cfg.get("email") or not cfg["email"].get("sender"):
        log("当前没有保存的邮件配置", "WARN")
        return False
    cfg["email"] = dict(DEFAULT_MAIL_CONFIG)
    save_config(cfg)
    log("邮件配置已删除", "OK")
    return True


def verify_saved_email(cfg):
    """验证邮件配置：发送一封测试邮件"""
    mail_cfg = cfg.get("email", {})
    sender = mail_cfg.get("sender", "")
    password = mail_cfg.get("password", "")
    receivers = mail_cfg.get("receivers", [])

    if not sender:
        log("未配置发件邮箱", "ERROR")
        return False
    if not password:
        log("未配置 SMTP 授权码", "ERROR")
        return False
    if not receivers:
        log("未配置收件邮箱", "ERROR")
        return False

    log(f"正在测试邮件服务 ({sender} -> {', '.join(receivers)})...", "INFO")
    test_content = (
        f"每日签到 — 邮件服务测试\n"
        f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"SMTP: {mail_cfg.get('smtp_host', 'smtp.qq.com')}:{mail_cfg.get('smtp_port', 465)}\n"
        f"此邮件表示邮件服务配置正确，可正常接收签到通知。"
    )
    result = send_mail(cfg, "每日签到 - 邮件测试", test_content)
    if result:
        log("邮件服务正常 ✅", "OK")
    else:
        log("邮件服务异常，请检查配置", "ERROR")
    return result


# ============ 邮件发送 ============


def send_mail(cfg, subject, content):
    """通过 SMTP 发送邮件通知"""
    mail_cfg = cfg.get("email", {})
    sender = mail_cfg.get("sender", "")
    password = mail_cfg.get("password", "")
    receivers = mail_cfg.get("receivers", [])

    if not sender or not password or not receivers:
        log("邮件配置不完整，跳过邮件通知", "WARN")
        return False

    msg = MIMEText(content, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = email.utils.formataddr(("Daily Sign", sender))
    msg["To"] = ", ".join(receivers)
    msg["Date"] = email.utils.formatdate(localtime=True)

    try:
        smtp_host = mail_cfg.get("smtp_host", "smtp.qq.com")
        smtp_port = mail_cfg.get("smtp_port", 465)
        use_ssl = mail_cfg.get("smtp_ssl", True)

        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                server.login(sender, password)
                server.sendmail(sender, receivers, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, receivers, msg.as_string())
        log(f"邮件通知已发送至 {', '.join(receivers)}", "OK")
        return True
    except smtplib.SMTPAuthenticationError:
        log("邮件发送失败: SMTP 认证失败，请检查授权码", "ERROR")
        return False
    except smtplib.SMTPException as e:
        log(f"邮件发送失败: {e}", "ERROR")
        return False
    except OSError as e:
        log(f"邮件发送失败 (网络): {e}", "ERROR")
        return False


# ============ Cookie 管理 ============


def parse_cookie(cookie_str):
    """解析 Cookie 字符串为字典"""
    cookies = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if "=" in item:
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def get_common_headers():
    """返回通用的请求头"""
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }


def verify_cookie(domain, cookies):
    """
    验证 Cookie 是否有效（能正常访问签到页面）
    返回 (有效, 用户名或提示)
    """
    url = f"https://{domain}{SIGN_PAGE}"
    try:
        resp = requests.get(url, cookies=cookies, headers=get_common_headers(), timeout=15)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}"

        if "formhash" in resp.text or "k_misign" in resp.text:
            m = re.search(r'<a[^>]*title="([^"]+)"[^>]*>\s*<img[^>]*avatar', resp.text)
            if m:
                return True, m.group(1)
            m = re.search(r'欢迎\s*([^<]+)\s*</', resp.text)
            if m:
                return True, m.group(1).strip()
            return True, "已登录"
        elif "请先登录" in resp.text or "您需要先登录" in resp.text:
            return False, "Cookie 已过期，请重新登录"
        else:
            return False, "无法确认登录状态"
    except requests.RequestException as e:
        return False, f"网络错误: {e}"


# ============ 账号密码登录 ============


def discuz_login(domain, username, password):
    """
    使用账号密码登录论坛 (Discuz!)，返回登录后的 Cookie 字符串
    失败返回 None
    """
    import hashlib

    login_page = f"https://{domain}/member.php?mod=logging&action=login"
    session = requests.Session()
    session.headers.update(get_common_headers())
    try:
        resp = session.get(login_page, timeout=15)
    except requests.RequestException as e:
        log(f"登录页请求失败: {e}", "ERROR")
        return None
    if resp.status_code != 200:
        log(f"登录页 HTTP {resp.status_code}", "WARN")
        return None

    # 提取 formhash
    m = re.search(r'name="formhash"\s+value="([a-zA-Z0-9]+)"', resp.text)
    if not m:
        log("登录页未找到 formhash，登录失败", "ERROR")
        return None
    formhash = m.group(1)

    # 提取 loginhash（表单 action 中）
    m = re.search(
        r'action="member\.php\?mod=logging&action=login&loginsubmit=yes&loginhash=([a-zA-Z0-9]+)"',
        resp.text,
    )
    loginhash = m.group(1) if m else ""

    post_url = (
        f"https://{domain}/member.php?mod=logging&action=login"
        f"&loginsubmit=yes" + (f"&loginhash={loginhash}" if loginhash else "")
    )
    data = {
        "formhash": formhash,
        "referer": f"https://{domain}/",
        "loginfield": "username",
        "username": username,
        "password": hashlib.md5(password.encode("utf-8")).hexdigest(),
        "questionid": "0",
        "answer": "",
        "cookietime": "2592000",
    }
    try:
        resp = session.post(
            post_url, data=data, timeout=15,
            headers={
                **get_common_headers(),
                "Referer": login_page,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    except requests.RequestException as e:
        log(f"登录请求失败: {e}", "ERROR")
        return None

    # 登录成功与否：检查 session 中是否出现 auth cookie
    cookies = session.cookies
    auth_cookie = [c for c in cookies if "auth" in c.name.lower()]
    if not auth_cookie:
        if "验证码" in resp.text:
            log("登录需要验证码，暂不支持自动登录", "ERROR")
        else:
            log(f"登录失败 (HTTP {resp.status_code})，未获取到 auth cookie", "ERROR")
        return None

    cookie_str = "; ".join(f"{c.name}={c.value}" for c in cookies)
    log(f"账号密码登录成功 (用户: {username})", "OK")
    return cookie_str


# ============ 域名管理 ============


def test_latency(domain, timeout=5):
    """测试域名的响应延迟"""
    url = f"https://{domain}/"
    start = time.time()
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers={"User-Agent": get_common_headers()["User-Agent"]},
        )
        elapsed = (time.time() - start) * 1000
        return int(elapsed), resp.status_code
    except requests.RequestException:
        elapsed = (time.time() - start) * 1000
        return int(elapsed), None


def pick_fastest_domain():
    """测试所有域名并返回最快的可用域名，7 天内复用优选域名"""
    # 检查是否有有效期内的优选域名
    preferred = get_preferred_domain()
    if preferred:
        log(f"使用优选域名: {preferred}（7 天有效期内）", "DEBUG")
        return preferred

    domains = load_domains_from_config()  # 从配置文件加载域名列表
    log("正在测试分流域名延迟...", "INFO")
    results = []
    for domain in domains:
        latency, status = test_latency(domain)
        status_str = str(status) if status else "超时"
        log(f"  {domain} -> {latency}ms (HTTP {status_str})", "DEBUG")
        if status and status < 500:
            # 优先权重: HTTP 200 (实际论坛) > 其他 (重定向/拦截)
            priority = 0 if status == 200 else 1
            results.append((priority, latency, domain))

    if not results:
        log("所有域名均不可达！请更新域名列表后重试", "ERROR")
        return None

    # 按优先级排序，同优先级按延迟排序
    results.sort()
    best = results[0][2]
    log(f"优选域名: {best} ({results[0][1]}ms)", "OK")
    # 将优选域名写入配置文件，记录时间戳
    set_preferred_domain(best)
    return best


def try_domains_for_formhash(cookies, preferred=None):
    """依次尝试各域名获取 formhash，返回 (domain, formhash)"""
    domains = load_domains_from_config()  # 从配置文件加载域名列表
    trial_order = list(domains)
    if preferred and preferred in trial_order:
        trial_order.remove(preferred)
        trial_order.insert(0, preferred)

    for domain in trial_order:
        log(f"  尝试 {domain} ...", "DEBUG")
        formhash = get_formhash(domain, cookies)
        if formhash:
            return domain, formhash
    return None, None


# ============ 签到核心功能 ============


def get_formhash(domain, cookies):
    """从签到页面获取 formhash"""
    url = f"https://{domain}{SIGN_PAGE}"
    try:
        resp = requests.get(url, cookies=cookies, headers=get_common_headers(), timeout=15)
    except requests.RequestException as e:
        log(f"请求失败: {e}", "ERROR")
        return None

    if resp.status_code != 200:
        log(f"获取签到页面失败: HTTP {resp.status_code}", "WARN")
        return None

    pattern = r'<input\s+[^>]*name="formhash"[^>]*value="([a-zA-Z0-9]+)"'
    match = re.search(pattern, resp.text, re.IGNORECASE)
    if match:
        return match.group(1)

    url2 = f"https://{domain}/plugin.php?id=k_misign:sign"
    try:
        resp2 = requests.get(url2, cookies=cookies, headers=get_common_headers(), timeout=15)
        if resp2.status_code == 200:
            match2 = re.search(pattern, resp2.text, re.IGNORECASE)
            if match2:
                return match2.group(1)
    except requests.RequestException:
        pass

    return None


def get_sign_info(domain, cookies):
    """
    获取签到信息
    返回 dict: {formhash, qiandaobtnnum, lxdays, lxtdays, lxlevel, lxreward, already_signed}
    或 None
    """
    url = f"https://{domain}{SIGN_PAGE}"
    try:
        resp = requests.get(url, cookies=cookies, headers=get_common_headers(), timeout=15)
    except requests.RequestException as e:
        log(f"获取签到信息失败: {e}", "ERROR")
        return None

    if resp.status_code != 200:
        return None

    info = {"formhash": None, "already_signed": False}
    for field in ["qiandaobtnnum", "lxdays", "lxtdays", "lxlevel", "lxreward"]:
        m = re.search(f'id="{field}"[^>]*value="([^"]+)"', resp.text)
        if m:
            info[field] = m.group(1)

    m = re.search(r'<input\s+[^>]*name="formhash"[^>]*value="([a-zA-Z0-9]+)"', resp.text, re.IGNORECASE)
    if m:
        info["formhash"] = m.group(1)

    info["already_signed"] = "今日已签" in resp.text

    m = re.search(r'<a[^>]*title="([^"]+)"[^>]*>\s*<img[^>]*avatar', resp.text)
    if m:
        info["username"] = m.group(1)

    return info


def do_sign(domain, cookies, formhash):
    """执行签到请求，返回结果字符串"""
    url = (
        f"https://{domain}{SIGN_API}"
        f"?id=k_misign:sign"
        f"&operation=qiandao"
        f"&formhash={formhash}"
        f"&format=empty"
        f"&inajax=1"
        f"&ajaxtarget="
    )

    try:
        resp = requests.get(
            url, cookies=cookies, timeout=15,
            headers={
                **get_common_headers(),
                "Referer": f"https://{domain}/k_misign-sign.html",
            },
        )
    except requests.RequestException as e:
        return f"签到请求失败: {e}"

    text = resp.text

    if "签到成功" in text:
        return "✅ 签到成功"
    elif "今日已签" in text:
        return "⏭️ 今日已签到"
    elif "请先登录" in text:
        return "❌ Cookie 已过期，请重新登录"
    elif "非法字符" in text:
        return "❌ 请求包含非法字符"
    else:
        cdata_match = re.search(r'<!\[CDATA\[(.*?)\]\]>', text, re.DOTALL)
        if cdata_match:
            content = cdata_match.group(1).strip()
            if not content:
                return "✅ 签到成功"
            return f"签到结果: {content}"
        return f"未知响应: {text[:200]}"


def do_makeup_sign(domain, cookies, formhash, bid):
    """
    执行补签
    bid: 补签记录 ID
    返回 (成功: bool, 消息: str)
    """
    url = f"https://{domain}{MAGIC_PAGE}?mod=magic&action=mybox&infloat=yes"
    data = {
        "formhash": formhash,
        "handlekey": "",
        "operation": "use",
        "magicid": "25",
        "bid": bid,
        "usesubmit": "yes",
    }

    try:
        resp = requests.post(
            url, cookies=cookies, data=data, timeout=15,
            headers={
                **get_common_headers(),
                "Referer": f"https://{domain}/home.php?mod=magic&mid=k_misign:k_misign_bq&bid={bid}",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    except requests.RequestException as e:
        return False, f"补签请求失败: {e}"

    if "操作成功" in resp.text or "成功" in resp.text:
        return True, "✅ 补签成功"
    elif "道具不足" in resp.text or "没有" in resp.text:
        return False, "❌ 补签卡不足"
    elif "积分不足" in resp.text or "余额不足" in resp.text:
        return False, "❌ 积分不足，无法购买补签卡"
    else:
        return False, f"补签失败: {resp.text[:200]}"


def check_makeup_needed(sign_info):
    """
    检查是否需要补签
    如果连续签到天数 = 1 且总签到天数 > 1，说明断签了，需要补签
    返回 (需要补签: bool, 建议: str)
    """
    if not sign_info:
        return False, "无法获取签到信息"

    if sign_info.get("already_signed"):
        lxdays = sign_info.get("lxdays")
        lxtdays = sign_info.get("lxtdays")
        if lxdays and lxtdays:
            lxdays = int(lxdays)
            lxtdays = int(lxtdays)
            if lxdays == 1 and lxtdays > 1:
                return True, f"连续签到仅 {lxdays} 天，总签到 {lxtdays} 天，可能断签，需要补签"
    return False, "无需补签"


def find_bid_list(domain, cookies):
    """
    获取可补签的日期列表
    从签到页 k_misign-sign.html 中提取 bid
    返回 [(bid, 日期描述), ...] 或 None
    """
    url = f"https://{domain}{SIGN_PAGE}"
    try:
        resp = requests.get(url, cookies=cookies, headers=get_common_headers(), timeout=15)
    except requests.RequestException as e:
        log(f"签到页请求失败 ({domain}): {e}", "ERROR")
        return None

    if resp.status_code != 200:
        log(f"签到页返回 HTTP {resp.status_code} ({domain})", "WARN")
        return None

    # 在签到页中查找补签 bid 列表，常见于含有 bid 参数的链接
    bids = re.findall(r'bid=(\d+)(?:[^>]*>([^<]+))?', resp.text)
    # 过滤掉明显不是补签日期的 bid（例如 formhash 中的数字等）
    valid = [(b, d.strip() if d.strip() else f"bid={b}") for b, d in bids if b.isdigit() and len(b) >= 4]
    if not valid:
        log(f"签到页未找到可补签的日期 ({domain})", "INFO")
        return None
    log(f"找到 {len(valid)} 个可补签日期 ({domain})", "DEBUG")
    return valid


# ============ 主流程 ============


def cli_commands():
    """处理 CLI 命令，返回 True 表示已处理并退出"""
    if len(sys.argv) < 2:
        return False

    cfg = load_config()
    cfg = ensure_config(cfg)

    cmd = sys.argv[1]

    if cmd == "--update-cookie":
        log_separator("更新 Cookie")
        update_cookie_interactive(cfg)
        return True

    if cmd == "--verify-cookie":
        log_separator("验证 Cookie")
        verify_saved_cookie(cfg)
        return True

    if cmd == "--delete-cookie":
        log_separator("删除 Cookie")
        delete_cookie(cfg)
        return True

    if cmd == "--update-email":
        log_separator("配置邮箱")
        update_email_interactive(cfg)
        return True

    if cmd == "--verify-email":
        log_separator("验证邮箱")
        verify_saved_email(cfg)
        return True

    if cmd == "--delete-email":
        log_separator("删除邮箱")
        delete_email(cfg)
        return True

    if cmd == "--menu":
        show_menu()
        return True

    log(f"未知参数: {cmd}", "ERROR")
    log("用法: python sijishe_sign.py [--menu | --update-cookie | --verify-cookie | --delete-cookie | --update-email | --verify-email | --delete-email]", "INFO")
    return True


def show_menu():
    """交互式菜单"""
    cfg = load_config()
    cfg = ensure_config(cfg)

    while True:
        print()
        print("=" * 55)
        print("  Discuz 论坛每日签到")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)
        print()
        print("  请选择操作:")
        print()
        print("    1. 自动签到")
        cookie_status = "已配置" if cfg.get("cookie") else "未配置"
        print(f"    2. 添加/更新 Cookie  [当前: {cookie_status}]")
        print(f"    3. 验证 Cookie")
        print(f"    4. 删除 Cookie")
        email_status = "已配置" if cfg.get("email", {}).get("sender") else "未配置"
        print(f"    5. 配置邮箱        [当前: {email_status}]")
        print(f"    6. 验证邮箱")
        print(f"    7. 删除邮箱")
        print("    0. 退出")
        print()
        print("=" * 55)

        choice = input("请输入数字 (0-7): ").strip()

        if choice == "1":
            print()
            main()
            input("\n按 Enter 键返回菜单...")

        elif choice == "2":
            log_separator("添加/更新 Cookie")
            update_cookie_interactive(cfg)
            cfg = load_config()
            cfg = ensure_config(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "3":
            log_separator("验证 Cookie")
            verify_saved_cookie(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "4":
            log_separator("删除 Cookie")
            delete_cookie(cfg)
            cfg = load_config()
            cfg = ensure_config(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "5":
            log_separator("配置邮箱")
            update_email_interactive(cfg)
            cfg = load_config()
            cfg = ensure_config(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "6":
            log_separator("验证邮箱")
            verify_saved_email(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "7":
            log_separator("删除邮箱")
            delete_email(cfg)
            cfg = load_config()
            cfg = ensure_config(cfg)
            input("\n按 Enter 键返回菜单...")

        elif choice == "0":
            print("再见！")
            break

        else:
            print("无效输入，请重新选择")


def main():
    log_separator(f"每日签到 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ---------- 加载配置 ----------
    cfg = load_config()
    cfg = ensure_config(cfg)

    # ---------- 认证：账号密码优先，Cookie 兜底 ----------
    cookie_str = cfg.get("cookie", "")
    account = cfg.get("account", {}) or {}
    username = account.get("username", "")
    password = account.get("password", "")

    if username and password:
        log("检测到账号密码，优先尝试登录刷新 Cookie...", "INFO")
        login_domain = get_preferred_domain()
        if not login_domain:
            domains = load_domains_from_config()
            login_domain = domains[0] if domains else None
        new_cookie = discuz_login(login_domain, username, password) if login_domain else None
        if new_cookie:
            cookie_str = new_cookie
            cfg["cookie"] = new_cookie
            save_config(cfg)
        else:
            log("账号密码登录失败，回退使用已保存的 Cookie", "WARN")

    if not cookie_str:
        log("首次运行，请先配置 Cookie 或账号密码", "INFO")
        if not update_cookie_interactive(cfg):
            return
        cookie_str = cfg["cookie"]

    cookies = parse_cookie(cookie_str)

    has_auth = any("auth" in k for k in cookies)
    has_saltkey = any("saltkey" in k for k in cookies)
    if not has_auth:
        log("Cookie 中未找到 auth 字段，可能无法正常登录", "WARN")
    if not has_saltkey:
        log("Cookie 中未找到 saltkey 字段", "WARN")

    # ---------- 优选域名 ----------
    domain = pick_fastest_domain()
    if not domain:
        return

    # ---------- 验证 Cookie 有效性（支持即时更新） ----------
    username = None
    for cookie_retry in range(3):
        log("正在验证 Cookie 有效性...", "INFO")
        valid, user_info = verify_cookie(domain, cookies)
        if valid:
            log(f"Cookie 有效 (用户: {user_info})", "OK")
            username = user_info
            break
        log(f"Cookie 无效: {user_info}", "ERROR")
        if cookie_retry < 2:
            log(f"请打开 https://{domain} 在浏览器中登录论坛，然后复制新 Cookie 粘贴到下方：", "INFO")
            log("提示: F12 -> 应用/Application -> Cookies -> 复制完整 Cookie 字符串", "INFO")
            log("直接按 Enter 跳过可继续使用旧 Cookie 尝试签到", "INFO")
            new_cookie = read_multiline()
            if new_cookie:
                cfg["cookie"] = new_cookie
                save_config(cfg)
                cookie_str = new_cookie
                cookies = parse_cookie(cookie_str)
                log("Cookie 已更新并保存", "OK")
                continue
            else:
                log("已跳过 Cookie 更新，将使用旧 Cookie 继续尝试签到", "WARN")
                break
    if not valid:
        log("Cookie 已过期，但仍尝试使用旧 Cookie 进行签到（可能失败）", "WARN")

    # ---------- 获取签到信息 ----------
    log("正在获取签到信息...", "INFO")
    sign_info = get_sign_info(domain, cookies)
    if not sign_info or not sign_info.get("formhash"):
        log("当前域名获取失败，尝试其他域名...", "INFO")
        new_domain, new_formhash = try_domains_for_formhash(cookies, preferred=domain)
        if new_domain and new_formhash:
            domain = new_domain
            sign_info = get_sign_info(domain, cookies)
        else:
            log("所有域名均无法获取签到信息", "ERROR")
            return

    formhash = sign_info.get("formhash")
    log(f"formhash: {formhash}", "DEBUG")

    if sign_info.get("lxdays"):
        log(f"连续签到: {sign_info['lxdays']} 天", "INFO")
    if sign_info.get("lxtdays"):
        log(f"总签到: {sign_info['lxtdays']} 天", "INFO")
    if sign_info.get("lxlevel"):
        log(f"签到等级: Lv.{sign_info['lxlevel']}", "INFO")
    if sign_info.get("lxreward"):
        log(f"签到奖励: {sign_info['lxreward']}", "INFO")

    # ---------- 收集报告 ----------
    report_lines = []
    report_lines.append(f"每日签到报告")
    report_lines.append(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if username:
        report_lines.append(f"用户: {username}")
    report_lines.append(f"域名: {domain}")
    if sign_info.get("lxdays"):
        report_lines.append(f"连续签到: {sign_info['lxdays']} 天")
    if sign_info.get("lxtdays"):
        report_lines.append(f"总签到: {sign_info['lxtdays']} 天")
    if sign_info.get("lxlevel"):
        report_lines.append(f"签到等级: Lv.{sign_info['lxlevel']}")
    if sign_info.get("lxreward"):
        report_lines.append(f"签到奖励: {sign_info['lxreward']}")
    report_lines.append("-" * 30)

    # ---------- 补签循环验证 ----------
    need_makeup, makeup_reason = check_makeup_needed(sign_info)
    makeup_total = 0
    if need_makeup:
        log(f"检测到可能需要补签: {makeup_reason}", "INFO")

        max_rounds = 30
        for round_i in range(1, max_rounds + 1):
            sign_info = get_sign_info(domain, cookies)
            if not sign_info:
                log("无法获取签到信息，终止补签", "WARN")
                break

            need_makeup, _ = check_makeup_needed(sign_info)
            if not need_makeup:
                if sign_info.get("lxdays"):
                    log(f"连续签到已恢复至 {sign_info['lxdays']} 天，补签完成", "OK")
                    report_lines.append(f"补签: 成功补签 {makeup_total} 天 ✅")
                    report_lines.append(f"连续签到: {sign_info['lxdays']} 天")
                break

            if sign_info.get("formhash"):
                formhash = sign_info["formhash"]

            log(f"第 {round_i} 轮补签: 查找可补签日期...", "INFO")
            bids = find_bid_list(domain, cookies)
            if not bids:
                log("未找到可补签的日期，补签结束", "WARN")
                if makeup_total > 0:
                    report_lines.append(f"补签: 成功补签 {makeup_total} 天 ✅")
                else:
                    report_lines.append("补签: 未找到可补签日期")
                break

            bid, desc = bids[0]
            log(f"补签日期: {desc} (bid={bid})", "INFO")

            ok, msg = do_makeup_sign(domain, cookies, formhash, bid)
            log(msg, "OK" if ok else "ERROR")
            if ok:
                makeup_total += 1
                new_fh = get_formhash(domain, cookies)
                if new_fh:
                    formhash = new_fh
            else:
                report_lines.append(f"补签: 第 {round_i} 轮失败 - {msg}")
                if makeup_total > 0:
                    report_lines.insert(-1, f"补签: 成功补签 {makeup_total} 天 ✅")
                break
        else:
            log(f"达到补签上限 {max_rounds} 轮，停止", "WARN")
            if makeup_total > 0:
                report_lines.append(f"补签: 成功补签 {makeup_total} 天 ✅")

        sign_info = get_sign_info(domain, cookies)
        if sign_info and sign_info.get("lxdays"):
            report_lines.append(f"连续签到: {sign_info['lxdays']} 天")
        if sign_info and sign_info.get("lxtdays"):
            report_lines.append(f"总签到: {sign_info['lxtdays']} 天")
    else:
        log(makeup_reason, "INFO")

    # ---------- 执行签到 ----------
    log("正在执行签到...", "INFO")
    sign_result = do_sign(domain, cookies, formhash)
    log(sign_result, "OK" if "✅" in sign_result else "INFO")
    report_lines.append(f"签到: {sign_result}")

    report_lines.append("-" * 30)
    report_lines.append(f"完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ---------- 状态界定 ----------
    # 已签到:本次运行完成了签到(存在断签时已一并补签,综合结果同为"已签到")
    # 今日已签到:今日已被签到过(非本次操作,避免同日多次触发时输出不明确)
    # 签到失败:签到操作未成功
    if "✅ 签到成功" in sign_result:
        current_state = SIGN_STATE_SIGNED
        final_result = "✅ 已签到" + ("（含补签）" if makeup_total > 0 else "")
    elif "⏭️" in sign_result or "今日已签" in sign_result:
        current_state = SIGN_STATE_ALREADY
        final_result = "⏭️ 今日已签到"
    else:
        current_state = SIGN_STATE_FAILED
        final_result = f"❌ 签到失败：{sign_result}"

    report_lines.append(f"结果: {final_result}")
    report_content = "\n".join(report_lines)
    print()  # 空行
    for line in report_lines:
        log(line, "INFO")
    print()

    # ---------- 邮件通知 ----------
    # 仅本次运行完成签到(已签到)时发送;今日已签到(重复触发)不重复发送
    if current_state == SIGN_STATE_SIGNED:
        email_cfg = cfg.get("email", {}) or {}
        if not (email_cfg.get("sender") and email_cfg.get("password") and email_cfg.get("receivers")):
            log("邮件通知: 未配置 SMTP，已跳过", "WARN")
        else:
            log("正在发送邮件通知...", "INFO")
            mail_ok = send_mail(cfg, f"每日签到 - {datetime.now().strftime('%m/%d')}", report_content)
            log("邮件通知: 已发送" if mail_ok else "邮件通知: 发送失败（请检查 SMTP 配置/授权码/网络）",
                "OK" if mail_ok else "ERROR")

    log(f"签到完成 - {final_result}", "OK" if current_state != SIGN_STATE_FAILED else "ERROR")


if __name__ == "__main__":
    # 先检查是否是 CLI 命令
    if not cli_commands():
        main()