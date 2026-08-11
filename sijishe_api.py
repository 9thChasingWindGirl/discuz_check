import sys
import json
import traceback
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout

# Windows 下 stdout 默认为 GBK，无法输出 Unicode 字符（如 ⏭️）
# 强制使用 UTF-8 编码以确保 JSON 输出正常
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# 确保能找到同目录的脚本
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

# 导入原脚本的功能
from sijishe_sign import (
    load_config, save_config, ensure_config,
    parse_cookie, get_common_headers,
    get_formhash, get_sign_info,
    do_makeup_sign, check_makeup_needed,
    find_bid_list, try_domains_for_formhash,
    verify_cookie, pick_fastest_domain,
    set_preferred_domain, get_preferred_domain,
    load_domains_from_config, save_domains_to_config,
    discover_domains, discuz_login,
    login_with_account, summarize_login_failures, retry_sign,
    resolve_final_state,
    load_last_sign_state, save_last_sign_state,
    load_sign_cache, save_sign_cache,
    beijing_now,
    SIGN_STATE_SIGNED, SIGN_STATE_ALREADY,
    SIGN_FINAL_SUCCESS,
    send_mail, sanitize_report_for_mail,
    SIGN_PAGE, SIGN_API, MAGIC_PAGE,
)


def cmd_config():
    """返回当前配置状态"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
    return {
        "success": True,
        "config": {
            "hasCookie": bool(cfg.get("cookie")),
            "hasAccount": bool(cfg.get("account", {}).get("username")),
            "email": cfg.get("email", {}),
        },
    }


def cmd_verify(cookie_str=None):
    """验证 Cookie"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        if not cookie_str:
            cookie_str = cfg.get("cookie", "")
    if not cookie_str:
        return {"success": False, "error": "Cookie 为空"}
    
    with redirect_stdout(StringIO()):
        cookies = parse_cookie(cookie_str)
        domain = pick_fastest_domain()
    if not domain:
        return {"success": False, "error": "所有域名均不可达"}
    
    with redirect_stdout(StringIO()):
        valid, user_info = verify_cookie(domain, cookies)
    if valid:
        return {"success": True, "username": user_info}
    return {"success": False, "error": user_info}


def cmd_info():
    """获取签到信息"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        cookie_str = cfg.get("cookie", "")
    if not cookie_str:
        return {"success": False, "error": "请先配置 Cookie"}
    
    with redirect_stdout(StringIO()):
        cookies = parse_cookie(cookie_str)
        domain = pick_fastest_domain()
    if not domain:
        return {"success": False, "error": "所有域名均不可达"}
    
    with redirect_stdout(StringIO()):
        sign_info = get_sign_info(domain, cookies)
        if not sign_info or not sign_info.get("formhash"):
            new_domain, new_fh = try_domains_for_formhash(cookies, preferred=domain)
            if new_domain and new_fh:
                domain = new_domain
                sign_info = get_sign_info(domain, cookies)
            else:
                return {"success": False, "error": "无法获取 formhash，请检查 Cookie 是否有效"}
    
    return {"success": True, "info": sign_info, "domain": domain}


def cmd_sign():
    """执行签到:env 模式下单次调用完成 账号认证→域名探寻→签到→补签→邮件,全程内存内"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
    report_lines = []
    now = beijing_now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines.append(f"每日签到报告")
    report_lines.append(f"时间: {now}")

    # ---------- 1. 认证:账号密码优先登录,失败回退存量 Cookie ----------
    auth_source = "未认证"
    auth_fallback_reason = ""
    with redirect_stdout(StringIO()):
        account = cfg.get("account", {}) or {}
        cookie_str = cfg.get("cookie", "")
        if account.get("username") and account.get("password"):
            login_domains = cfg.get("domains") or load_domains_from_config()
            # 依次尝试多个域名登录(内部含网络重试):首个被 Cloudflare 拦截/失败时继续尝试下一个
            new_cookie, login_errors = login_with_account(cfg, login_domains)
            if new_cookie:
                cookie_str = new_cookie
                cfg["cookie"] = new_cookie  # env 模式不落盘,仅内存
                auth_source = f"账号密码 ({account['username']})"
            elif login_errors:
                # 摘要化:只保留"域名+失败类型",原始异常文本仅留在控制台日志
                auth_fallback_reason = "账号密码登录失败: " + summarize_login_failures(login_errors)
            else:
                auth_fallback_reason = "账号密码登录失败: 无可用域名"
    if not cookie_str:
        return {"success": False, "error": "未配置账号密码或 Cookie", "domains": []}
    if auth_source == "未认证":
        auth_source = "存量 Cookie"
    report_lines.append(f"认证方式: {auth_source}")
    if auth_fallback_reason:
        report_lines.append(f"认证回退原因: {auth_fallback_reason}")

    with redirect_stdout(StringIO()):
        cookies = parse_cookie(cookie_str)

    # ---------- 2. 域名自动探寻(内存内,基于 env 种子合并) ----------
    with redirect_stdout(StringIO()):
        seed = cfg.get("domains") or None
        domains = discover_domains(seed_domains=seed)
    if not domains:
        return {"success": False, "error": "未配置 SJS_DOMAINS 或所有域名均不可达", "domains": []}

    # ---------- 3. 在可用域名中选取能获取 formhash 的域名 ----------
    with redirect_stdout(StringIO()):
        domain = None
        formhash = None
        for d in domains:
            fh = get_formhash(d, cookies)
            if fh:
                domain, formhash = d, fh
                break
    if not domain or not formhash:
        return {
            "success": False,
            "error": "无法获取 formhash",
            "report": "\n".join(report_lines),
            "domains": domains,
        }
    report_lines.append(f"域名: {domain}")
    report_lines.append(f"formhash: {formhash}")
    
    with redirect_stdout(StringIO()):
        # 获取签到信息
        sign_info = get_sign_info(domain, cookies)
    if sign_info:
        if sign_info.get("lxdays"):
            report_lines.append(f"连续签到: {sign_info['lxdays']} 天")
        if sign_info.get("lxtdays"):
            report_lines.append(f"总签到: {sign_info['lxtdays']} 天")
        if sign_info.get("lxlevel"):
            report_lines.append(f"签到等级: Lv.{sign_info['lxlevel']}")
        if sign_info.get("lxreward"):
            report_lines.append(f"签到奖励: {sign_info['lxreward']}")
    
    report_lines.append("-" * 30)

    # 第一步：执行签到(带失败分类的多级重试:退避重试→Cookie 失效重登录→换域名)
    with redirect_stdout(StringIO()):
        sign_result, used_domain, cookies = retry_sign(cfg, domains, cookies, domain=domain)
    if used_domain and used_domain != domain:
        domain = used_domain
        report_lines.append(f"切换域名: {domain}")
    if "无法获取 formhash" in sign_result:
        return {
            "success": False,
            "error": sign_result,
            "report": "\n".join(report_lines),
            "domains": domains,
        }

    # 第二步：获取签到后的最新信息，判断是否断签
    need_makeup = False
    with redirect_stdout(StringIO()):
        post_sign_info = get_sign_info(domain, cookies)
    if post_sign_info:
        lxdays = post_sign_info.get("lxdays")
        lxtdays = post_sign_info.get("lxtdays")
        # 判断断签：连续签到 1 天但总签到 > 1 天
        if lxdays and lxtdays and int(lxdays) == 1 and int(lxtdays) > 1:
            need_makeup = True
            report_lines.append(f"检测到可能断签（连续 {lxdays} 天 / 总 {lxtdays} 天），尝试补签...")
            makeup_total = 0
            with redirect_stdout(StringIO()):
                bid_list = find_bid_list(domain, cookies)
            if bid_list:
                # 刷新 formhash
                with redirect_stdout(StringIO()):
                    new_fh = get_formhash(domain, cookies)
                    if new_fh:
                        formhash = new_fh
                for i, (bid, desc) in enumerate(bid_list, 1):
                    report_lines.append(f"第 {i} 轮补签: {desc} (bid={bid})")
                    with redirect_stdout(StringIO()):
                        ok, mmsg = do_makeup_sign(domain, cookies, formhash, bid)
                    if ok:
                        report_lines.append(f"✅ 补签成功 ({desc})")
                        makeup_total += 1
                        with redirect_stdout(StringIO()):
                            new_fh = get_formhash(domain, cookies)
                            if new_fh:
                                formhash = new_fh
                    elif "补签卡不足" in mmsg:
                        report_lines.append(f"❌ {mmsg}，停止补签")
                        break
                    elif "积分不足" in mmsg:
                        report_lines.append(f"❌ {mmsg}，停止补签")
                        break
                    else:
                        report_lines.append(mmsg)
                        break
                if makeup_total > 0:
                    report_lines.append(f"补签完成: 成功补签 {makeup_total} 天")
                    # 补签后刷新签到信息
                    with redirect_stdout(StringIO()):
                        fresh_info = get_sign_info(domain, cookies)
                    if fresh_info:
                        if fresh_info.get("lxdays"):
                            report_lines.append(f"补签后连续签到: {fresh_info['lxdays']} 天")
                        if fresh_info.get("lxtdays"):
                            report_lines.append(f"补签后总签到: {fresh_info['lxtdays']} 天")
            else:
                # 没有找到可补签日期，输出诊断信息
                report_lines.append("未找到可补签的日期，跳过补签")
            report_lines.append("-" * 30)

    # 断签是否已恢复(供最终状态判定:成功 = 签到成功 + 连续签到达成)
    makeup_ok = True
    if need_makeup:
        with redirect_stdout(StringIO()):
            final_info = get_sign_info(domain, cookies)
        lx_after = int(final_info.get("lxdays", 0)) if final_info else 0
        lxt_after = int(final_info.get("lxtdays", 0)) if final_info else 0
        makeup_ok = lx_after > 1 or lxt_after <= 1

    report_lines.append(f"完成时间: {beijing_now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ---------- 最终状态判定 ----------
    # 成功 = 签到成功(含 Cookie 兜底)且连续签到达成(无断签或断签已补)
    # 认证方式不影响结果:账号密码登录失败、Cookie 兜底签到成功同样是"签到成功"
    final_state, conclusion, action_state = resolve_final_state(sign_result, need_makeup, makeup_ok)
    final_result = conclusion

    # 结论先行:插入报告首行,让邮件/控制台第一眼看到是否成功
    report_lines.insert(0, conclusion + "\n")
    report_content = "\n".join(report_lines)

    # 保存本次动作状态(env 模式下不落盘)
    with redirect_stdout(StringIO()):
        save_last_sign_state(action_state)

    # ---------- 邮件通知 ----------
    # 成功(success):发签到成功报告;失败(break/failed):发告警邮件
    # 去重规则:
    #   - 成功但本次无实际动作(纯重复触发 ALREADY 且无补签)且当日缓存已成功 → 不发
    #   - 失败且当日缓存已是成功 → 不发(与"失败不覆盖当日成功缓存"一致,避免误报)
    today = beijing_now().strftime("%Y-%m-%d")
    cache = load_sign_cache()
    cache_success_today = bool(cache and cache.get("date") == today and cache.get("state") == SIGN_FINAL_SUCCESS)
    acted = action_state == SIGN_STATE_SIGNED or (action_state == SIGN_STATE_ALREADY and need_makeup)
    email_cfg = cfg.get("email", {}) or {}
    mail_configured = bool(email_cfg.get("sender") and email_cfg.get("password") and email_cfg.get("receivers"))
    mail_note = ""
    if final_state == SIGN_FINAL_SUCCESS:
        if acted or not cache_success_today:
            if not mail_configured:
                mail_note = "邮件通知: 未配置 SMTP，已跳过"
            else:
                with redirect_stdout(StringIO()):
                    mail_ok = send_mail(
                        cfg,
                        f"每日签到 - {beijing_now().strftime('%m/%d')}",
                        sanitize_report_for_mail(report_content),
                    )
                mail_note = "邮件通知: 已发送" if mail_ok else "邮件通知: 发送失败（请检查 SMTP 配置/授权码/网络）"
        else:
            mail_note = "邮件通知: 重复触发且当日已成功，未发送"
    else:
        if cache_success_today:
            mail_note = "邮件通知: 当日已签到成功，失败不打扰"
        else:
            if not mail_configured:
                mail_note = "邮件通知(告警): 未配置 SMTP，已跳过（签到失败，请及时处理）"
            else:
                with redirect_stdout(StringIO()):
                    mail_ok = send_mail(
                        cfg,
                        f"签到失败告警 - {beijing_now().strftime('%m/%d')}",
                        sanitize_report_for_mail(report_content),
                    )
                mail_note = "邮件通知(告警): 已发送" if mail_ok else "邮件通知(告警): 发送失败（请检查 SMTP 配置）"
    report_lines.append(mail_note)
    report_lines.append(f"结果: {final_result}")
    report_content = "\n".join(report_lines)

    # 当日签到结果写入缓存(成功覆盖失败,失败不覆盖当日成功记录)
    with redirect_stdout(StringIO()):
        save_sign_cache(final_state, final_result, report_content, domains)

    return {
        "success": final_state == SIGN_FINAL_SUCCESS,
        "state": final_state,
        "result": final_result,
        "report": report_content,
        "domains": domains,
    }


def cmd_send_cached_mail():
    """(调试)读取当日缓存签到结果并通过邮件发送,邮件内容注明来源为缓存"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        cache = load_sign_cache()
    if not cache:
        return {"success": False, "error": "无缓存签到结果,请先运行 sign"}

    report = cache.get("report", "")
    result = cache.get("result", "")
    state = cache.get("state", "")
    date_str = cache.get("date", "")
    header = (
        f"【调试】邮件内容来自签到结果缓存(非本次实时签到)\n"
        f"缓存日期: {date_str}\n"
        f"缓存状态: {state} | {result}\n"
        f"{'=' * 30}\n"
    )
    content = header + sanitize_report_for_mail(report)
    subject = f"每日签到(缓存) - {beijing_now().strftime('%m/%d')}"

    email_cfg = cfg.get("email", {}) or {}
    if not (email_cfg.get("sender") and email_cfg.get("password") and email_cfg.get("receivers")):
        return {"success": False, "error": "邮件通知: 未配置 SMTP，已跳过", "cache": cache}
    with redirect_stdout(StringIO()):
        mail_ok = send_mail(cfg, subject, content)
    if not mail_ok:
        return {"success": False, "error": "邮件发送失败(请检查 SMTP 配置/授权码/网络)", "cache": cache}
    return {
        "success": True,
        "message": f"已发送缓存签到结果邮件 (缓存日期 {date_str})",
        "cache_state": state,
        "cache_result": result,
    }


def cmd_discover_domains(seed_domains=None):
    """自动探寻可用的镜像分流域名并更新配置"""
    with redirect_stdout(StringIO()):
        domains = discover_domains(seed_domains=seed_domains)
    return {
        "success": True,
        "domains": domains,
        "count": len(domains),
        "message": f"域名自动探寻完成，共 {len(domains)} 个可用域名",
    }


def cmd_get_domains():
    """获取当前域名列表"""
    with redirect_stdout(StringIO()):
        domains = load_domains_from_config()
    return {
        "success": True,
        "domains": domains,
        "preferred_domain": load_config().get("preferred_domain", ""),
    }


def cmd_update_domains(domains_list):
    """更新域名列表"""
    if not domains_list or not isinstance(domains_list, list):
        return {"success": False, "error": "域名列表格式不正确"}
    with redirect_stdout(StringIO()):
        save_domains_to_config(domains_list)
    return {
        "success": True,
        "domains": domains_list,
        "message": f"域名列表已更新，共 {len(domains_list)} 个域名",
    }


def cmd_update_email(email_data):
    """更新邮箱配置"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        cfg["email"] = email_data
        save_config(cfg)
    return {"success": True, "message": "邮箱配置已保存"}


def cmd_delete_email():
    """删除邮箱配置"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        cfg["email"] = {}
        save_config(cfg)
    return {"success": True, "message": "邮箱配置已删除"}


def cmd_login(username=None, password=None):
    """使用账号密码登录并保存 Cookie（账号密码优先的认证入口）"""
    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        if not username:
            username = cfg.get("account", {}).get("username", "")
        if not password:
            password = cfg.get("account", {}).get("password", "")
    if not username or not password:
        return {"success": False, "error": "缺少用户名或密码"}

    with redirect_stdout(StringIO()):
        domain = pick_fastest_domain()
    if not domain:
        return {"success": False, "error": "所有域名均不可达"}

    with redirect_stdout(StringIO()):
        cookie_str, login_err = discuz_login(domain, username, password)
    if not cookie_str:
        return {"success": False, "error": f"登录失败 ({domain}): {login_err}"}

    with redirect_stdout(StringIO()):
        cfg = load_config()
        cfg = ensure_config(cfg)
        cfg["cookie"] = cookie_str
        save_config(cfg)
    return {"success": True, "domain": domain, "username": username}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"success": False, "error": "缺少命令参数"}))
        sys.exit(1)
    
    command = sys.argv[1]
    
    try:
        if command == "config":
            result = cmd_config()
        elif command == "verify":
            cookie = sys.argv[2] if len(sys.argv) > 2 else None
            result = cmd_verify(cookie)
        elif command == "info":
            result = cmd_info()
        elif command == "sign":
            result = cmd_sign()
        elif command == "send_cached_mail":
            result = cmd_send_cached_mail()
        elif command == "update_email":
            email_json = sys.argv[2] if len(sys.argv) > 2 else "{}"
            result = cmd_update_email(json.loads(email_json))
        elif command == "delete_email":
            result = cmd_delete_email()
        elif command == "login":
            username = sys.argv[2] if len(sys.argv) > 2 else None
            password = sys.argv[3] if len(sys.argv) > 3 else None
            result = cmd_login(username, password)
        elif command == "discover":
            seed_json = sys.argv[2] if len(sys.argv) > 2 else "[]"
            result = cmd_discover_domains(json.loads(seed_json))
        elif command == "get_domains":
            result = cmd_get_domains()
        elif command == "update_domains":
            domains_json = sys.argv[2] if len(sys.argv) > 2 else "[]"
            result = cmd_update_domains(json.loads(domains_json))
        else:
            result = {"success": False, "error": f"未知命令: {command}"}
    except Exception as e:
        result = {"success": False, "error": str(e), "traceback": traceback.format_exc()}
    
    print(json.dumps(result, ensure_ascii=False, default=str, indent=2))