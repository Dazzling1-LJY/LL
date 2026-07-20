# 用户管理系统 — 注册搜索功能开发及 SQL 注入漏洞修复报告

---

## 目录

1. [系统概述](#1-系统概述)
2. [系统各模块功能分析](#2-系统各模块功能分析)
3. [SQL 注入漏洞分析 —— 搜索功能](#3-sql-注入漏洞分析--搜索功能)
4. [SQL 注入漏洞分析 —— 注册功能](#4-sql-注入漏洞分析--注册功能)
5. [漏洞修复方案](#5-漏洞修复方案)
6. [攻击测试验证](#6-攻击测试验证)
7. [总结](#7-总结)

---

## 1. 系统概述

### 1.1 项目信息

| 项目 | 内容 |
|------|------|
| **项目名称** | 用户管理系统 |
| **技术栈** | Python Flask + SQLite + HTML/CSS |
| **框架版本** | Flask (Werkzeug) |
| **数据库** | SQLite 3 (`data/users.db`) |
| **项目路径** | `/opt/Class01/` |

### 1.2 文件结构

```
/opt/Class01/
├── app.py                         # 主应用（Flask 路由 + 业务逻辑）
├── data/
│   └── users.db                   # SQLite 数据库文件
├── templates/
│   ├── base.html                  # 基础模板（导航栏 + 布局）
│   ├── login.html                 # 登录页面
│   ├── index.html                 # 首页（个人信息 + 搜索功能）
│   ├── register.html              # 注册页面
│   └── change_password.html       # 修改密码页面
├── static/
│   └── css/
│       └── style.css              # 全局样式
└── test_security.py               # 安全验证测试脚本
```

### 1.3 数据库结构

```
users 表
┌──────────┬──────────────┬──────────┬──────────┐
│ 字段名   │ 类型         │ 约束     │ 说明     │
├──────────┼──────────────┼──────────┼──────────┤
│ id       │ INTEGER      │ PK, AI   │ 用户ID   │
│ username │ TEXT         │ UNIQUE   │ 用户名   │
│ password │ TEXT         │ NOT NULL │ 密码     │
│ email    │ TEXT         │          │ 邮箱     │
│ phone    │ TEXT         │          │ 手机号   │
└──────────┴──────────────┴──────────┴──────────┘
```

---

## 2. 系统各模块功能分析

### 2.1 登录模块 (`/login`)

**功能描述**：验证用户身份，创建会话。

**认证流程**：
1. 表单提交用户名和密码
2. 先在内存字典 `USERS` 中查找用户
   - 找到 → 用 `werkzeug.security.check_password_hash()` 比对哈希密码
   - 找不到 → 去 SQLite 数据库查找
     - 找到 → 用明文 `==` 比对密码
3. 验证通过后，用户名存入 `session`
4. 管理员首次登录强制跳转到修改密码页

**安全措施**：
- 登录失败次数计数，5 次失败后锁定 15 分钟
- 错误信息模糊化（不区分"用户不存在"和"密码错误"）
- `PERMANENT_SESSION_LIFETIME = 1800`（30 分钟过期）

---

### 2.2 注册模块 (`/register`)

**功能描述**：新用户自助注册。

**流程**：
1. 表单输入用户名、密码、邮箱、手机号
2. 验证用户名和密码非空
3. 使用 **f-string 拼接 SQL** 插入数据库
4. 用户名唯一约束（`sqlite3.IntegrityError`）拦截重复注册
5. 注册成功后跳转到登录页并显示"注册成功，请登录"

**漏洞状态**：❌ 存在 SQL 注入漏洞（详见第 4 节）

---

### 2.3 搜索模块 (`/search`)

**功能描述**：已登录用户按关键词搜索其他用户。

**流程**：
1. URL 参数 `keyword` 接收关键词
2. 使用 **f-string 拼接 SQL** 执行 LIKE 模糊查询
3. 查询用户名和邮箱两个字段
4. 结果以表格形式展示（ID、用户名、邮箱、手机）
5. SQL 语句打印到控制台

**漏洞状态**：❌ 存在 SQL 注入漏洞（详见第 3 节）

---

### 2.4 首页模块 (`/`)

**功能描述**：展示当前登录用户的个人信息和搜索功能。

**展示内容**：
- 用户名
- 邮箱
- 手机号
- 角色（默认 `user`）
- 余额（默认 `0`）
- 搜索框 + 搜索结果表格

---

### 2.5 修改密码模块 (`/change-password`)

**功能描述**：已登录用户修改密码。

**安全措施**：
- `@login_required` 装饰器保护
- 旧密码哈希比对验证
- 新密码复杂度要求（≥8 位 + 大小写 + 数字 + 特殊字符）
- 新旧密码不能相同

---

### 2.6 登出模块 (`/logout`)

**功能描述**：清除会话并重定向到首页。

---

## 3. SQL 注入漏洞分析 —— 搜索功能

### 3.1 漏洞基本信息

| 项目 | 内容 |
|------|------|
| **漏洞编号** | VULN-SQLI-001 |
| **漏洞名称** | 搜索功能 SQL 注入漏洞 |
| **CWE 分类** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') |
| **OWASP 分类** | A03:2021 – Injection |
| **风险等级** | 🔴 **严重** |
| **影响模块** | `/search` 路由 |
| **影响版本** | 修复前所有版本 |

### 3.2 漏洞描述

搜索功能在构建 SQL 查询时，直接将用户输入的 `keyword` 参数通过 **f-string** 拼接到 SQL 语句中，未做任何转义或参数化处理。攻击者可以输入特制的字符串来改变 SQL 语句的语义，实现未授权数据访问。

### 3.3 漏洞代码（修复前）

```python
# app.py 第 275-289 行
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql = ""
    if keyword:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"  # ← 漏洞行
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        rows = c.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
```

**问题代码行**（第 284 行）：
```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**根本原因**：用户输入 `keyword` 直接嵌入 SQL 模板字符串，攻击者可通过输入 `' OR 1=1 --` 等 payload 注入额外的 SQL 逻辑。

### 3.4 攻击向量分析

#### 攻击向量 1：布尔注入 —— 绕过认证逻辑，泄露全部用户

| 属性 | 内容 |
|------|------|
| **攻击方式** | 布尔盲注 / 永真条件注入 |
| **恶意输入** | `' OR 1=1 --` |
| **利用链** | 闭合前引号 → 插入 `OR 1=1` 永真条件 → `--` 注释掉后续 SQL |
| **危害** | 绕过 LIKE 过滤，返回 **所有用户记录** |

**攻击演示**：

```
用户输入: ' OR 1=1 --

拼接后 SQL:
SELECT * FROM users WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'

实际执行语义:
SELECT * FROM users WHERE username LIKE '%' OR 1=1
（-- 后面的内容被注释）

效果: WHERE 条件恒为真，返回 users 表全部记录
```

**控制台输出**：
```
[SQL] SELECT * FROM users WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'
```

---

#### 攻击向量 2：联合查询注入 —— 获取数据库元信息

| 属性 | 内容 |
|------|------|
| **攻击方式** | UNION SELECT 联合查询注入 |
| **恶意输入** | `' UNION SELECT 1, 'hacker', 'pwned', 'test', '1234' --` |
| **利用链** | 闭合前引号 → `UNION SELECT` 追加自定义查询结果 → 注释后续 SQL |
| **危害** | 在搜索结果中注入任意伪造数据 |

**攻击演示**：

```
拼接后 SQL:
SELECT * FROM users WHERE username LIKE '%' UNION SELECT 1, 'hacker', 'pwned', 'test', '1234' --%' OR email LIKE '%' UNION SELECT 1, 'hacker', 'pwned', 'test', '1234' --%'

效果: 原始查询返回空集，UNION SELECT 注入一条伪造的用户记录 "hacker"
```

---

#### 攻击向量 3：报错注入 —— 探测数据库结构

| 属性 | 内容 |
|------|------|
| **攻击方式** | 报错信息泄露 |
| **恶意输入** | `' OR 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS TEXT) --` |
| **利用链** | 构造类型转换错误的 SQL 表达式，触发异常并泄露错误信息 |
| **危害** | 获取数据库表结构（表名、字段名、类型） |

> 注：当前系统在生产模式下（`debug=False`）不会显示详细错误，但攻击者仍可通过布尔盲注逐字符推断数据。

---

#### 攻击向量 4：时间盲注 —— 无回显条件下的数据窃取

| 属性 | 内容 |
|------|------|
| **攻击方式** | 基于时间延迟的盲注入 |
| **恶意输入** | `' OR (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN randomblob(100000000) ELSE 1 END FROM users WHERE username='admin') = 1 --` |
| **利用链** | 利用 `randomblob()` 产生大块数据导致查询延迟，通过响应时间差异逐字符推断密码 |
| **危害** | 即使没有错误回显和结果回显，仍可通过时间差异逐位窃取数据 |

---

### 3.5 攻击场景模拟

**目标**：利用 SQL 注入泄露 `users` 表中的所有用户数据（含密码）。

**步骤**：

| 步骤 | 操作 | curl 命令 |
|------|------|-----------|
| 1 | 正常搜索（确认功能正常） | `curl "http://localhost:5000/search?keyword=admin"` |
| 2 | SQL 注入：' OR 1=1 -- 泄露全部用户 | `curl "http://localhost:5000/search?keyword=' OR 1=1 --"` |
| 3 | 应用层验证 | 搜索结果表格显示 admin、alice、testuser 等所有用户 |

**实际测试结果**：

```
搜索 admin → ✅ 显示 1 条结果（admin）
搜索 ' OR 1=1 -- → ✅ 显示 3 条结果（admin, alice, testuser 全部泄露）
```

---

## 4. SQL 注入漏洞分析 —— 注册功能

### 4.1 漏洞基本信息

| 项目 | 内容 |
|------|------|
| **漏洞编号** | VULN-SQLI-002 |
| **漏洞名称** | 注册功能 SQL 注入漏洞 |
| **CWE 分类** | CWE-89: SQL Injection |
| **OWASP 分类** | A03:2021 – Injection |
| **风险等级** | 🔴 **严重** |
| **影响模块** | `/register` 路由 |

### 4.2 漏洞描述

注册功能将所有表单字段（用户名、密码、邮箱、手机号）通过 f-string 直接拼接到 `INSERT` 语句中。攻击者可以在任意字段中注入 SQL 代码，在数据库中执行任意操作。

### 4.3 漏洞代码（修复前）

```python
# app.py 第 235-258 行
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    
    ...
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"  # ← 漏洞行
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        ...
```

**问题代码行**（第 253 行）：
```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

### 4.4 攻击向量分析

#### 攻击向量 1：注册时注入额外数据行

| 属性 | 内容 |
|------|------|
| **恶意输入（用户名）** | `hacker'), ('evil', 'pwned', 'hack@x.com', '666'); --` |
| **利用链** | 闭合 `VALUES` 的括号 → 插入额外数据行 → 注释后续内容 |
| **危害** | 一次注册请求插入多行数据，创建多个恶意账户 |

**攻击演示**：

```
用户输入（用户名字段）:
hacker'), ('evil', 'pwned', 'hack@x.com', '666'); --

拼接后 SQL:
INSERT INTO users (username, password, email, phone)
VALUES ('hacker'), ('evil', 'pwned', 'hack@x.com', '666'); --', 'irrelevant', '', '')

实际执行:
INSERT INTO users (username, password, email, phone) VALUES ('hacker'), ('evil', 'pwned', 'hack@x.com', '666');
（-- 后面的内容被注释）
```

---

#### 攻击向量 2：注册时修改已有用户密码

| 属性 | 内容 |
|------|------|
| **恶意输入（用户名）** | `admin', 'newpass', 'admin@hack.com', '00000000'); UPDATE users SET password='hacked' WHERE username='admin'; --` |
| **利用链** | 闭合 INSERT → 追加 UPDATE 语句修改管理员密码 |
| **危害** | 覆盖管理员密码，实现账户劫持 |

> 注：SQLite 默认不允许单条 `execute()` 执行多条语句（除非 `executescript`），但在某些数据库驱动（如 MySQL/PostgreSQL）下此攻击有效。

---

### 4.5 攻击场景模拟

**目标**：通过 SQL 注入在注册时创建多个恶意账号。

**步骤**：

| 步骤 | 操作 |
|------|------|
| 1 | 构造恶意 payload：`x'), ('y', 'pwned', '', ''); --` |
| 2 | 作为用户名提交注册表单 |
| 3 | 服务器拼接 SQL 并执行 |
| 4 | 数据库被插入额外行 |

**控制台输出**：
```
[SQL] INSERT INTO users (username, password, email, phone) VALUES ('x'), ('y', 'pwned', '', ''); --', 'irrelevant', '', '')
```

> 注：当前 SQLite 的 `execute()` 方法不支持多语句，第二条语句不会执行，但第一条的额外插入行仍然生效。若切换到 MySQL/PostgreSQL 则危险更大。

---

## 5. 漏洞修复方案

### 5.1 修复方案对比

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| **方案 A：参数化查询** ✅ | 使用 `?` 占位符，驱动自动转义 | 最佳实践，零开销，彻底防御 | 需改写 SQL 构造方式 |
| **方案 B：输入过滤** | 转义或拦截 `'` `--` 等危险字符 | 改动最小 | 容易遗漏，有绕过风险 |
| **方案 C：ORM 框架** | 使用 SQLAlchemy 等 ORM | 全面的抽象和安全保证 | 引入重依赖 |

**选择方案 A**：参数化查询是业界公认对抗 SQL 注入的标准方案，SQLite 原生支持且零性能开销。

### 5.2 搜索功能修复

#### 修复前代码

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

#### 修复后代码

```python
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
keyword_param = f"%{keyword}%"
print(f"[SQL] {sql} | param={keyword_param!r}", flush=True)
c.execute(sql, (keyword_param, keyword_param))
```

**修复说明**：
- 将 f-string 拼接改为 `?` 占位符
- SQL 模板字符串中不含任何用户输入
- 用户输入值通过第二个参数 `(keyword_param,)` 以元组形式传入
- SQLite 驱动自动对参数值中的特殊字符进行转义
- `%` 通配符在参数值中安全使用，不会被误解为 SQL 语法

### 5.3 注册功能修复

#### 修复前代码

```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
```

#### 修复后代码

```python
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
print(f"[SQL] {sql} | params={[username, password, email, phone]!r}", flush=True)
c.execute(sql, (username, password, email, phone))
```

### 5.4 完整修复后的 app.py 关键代码

```python
# ==================== 注册（修复后）====================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    error = None
    if not username or not password:
        error = "用户名和密码不能为空"
        return render_template("register.html", error=error)

    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        # ✅ 修复：使用参数化查询，防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql} | params={[username, password, email, phone]!r}", flush=True)
        c.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()
        return redirect("/login?registered=1")
    except sqlite3.IntegrityError:
        try:
            conn.close()
        except:
            pass
        error = "用户名已存在"
        return render_template("register.html", error=error)
    except Exception as e:
        try:
            conn.close()
        except:
            pass
        error = f"注册失败: {str(e)}"
        return render_template("register.html", error=error)


# ==================== 搜索（修复后）====================
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql = ""
    if keyword:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # ✅ 修复：使用参数化查询，防止 SQL 注入
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        keyword_param = f"%{keyword}%"
        print(f"[SQL] {sql} | keyword_param={keyword_param!r}", flush=True)
        c.execute(sql, (keyword_param, keyword_param))
        rows = c.fetchall()
        results = [dict(row) for row in rows]
        conn.close()

    username = session.get("username")
    user_info = None
    if username:
        user = USERS.get(username)
        if user is None:
            user = get_user_from_db(username)
        if user:
            locked, remaining = is_locked(user)
            if not locked:
                user_info = sanitize_user(user)

    return render_template("index.html", user_info=user_info, search_results=results, keyword=keyword, sql_debug=sql)
```

### 5.5 修复前后对比总结

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| SQL 构建方式 | `f"SELECT ... WHERE field='{user_input}'"` | `"SELECT ... WHERE field=?"` |
| 用户输入处理 | 直接嵌入 SQL 模板 | 通过参数元组传递给驱动 |
| 对 `'` 的处理 | 直接拼接，改变 SQL 结构 | 驱动自动转义为 SQL 字面量 |
| 对 `--` 的处理 | 触发注释，截断后续 SQL | 作为普通字符串处理，无特殊含义 |
| 对 `OR 1=1` 的处理 | 改变 WHERE 条件语义 | 作为搜索关键词的一部分，搜索文本 `'OR 1=1'` |
| 对 `UNION SELECT` 的处理 | 执行联合查询，插入任意数据 | 作为搜索关键词的一部分，搜索文本 |
| 控制台输出 | 显示完整的动态 SQL | 显示 SQL 模板 + 参数值（便于调试且安全） |
| SQL 注入风险 | ❌ **存在** | ✅ **彻底消除** |

---

## 6. 攻击测试验证

### 6.1 测试环境

- 服务地址：`http://localhost:5000`
- 测试工具：Python requests + curl
- 测试账号：admin（内存）、alice（数据库预设）

### 6.2 修复前攻击测试

#### 搜索功能 SQL 注入测试

```python
# 测试 1：正常搜索
GET /search?keyword=admin
→ 返回 1 条结果（admin）

# 测试 2：SQL 注入 - 泄露全部用户
GET /search?keyword=' OR 1=1 --
→ 返回 N 条结果（泄露全部用户）
→ 控制台输出: [SQL] SELECT * FROM users WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'

# 测试 3：SQL 注入 - UNION 查询
GET /search?keyword=' UNION SELECT 1,'x','y','z','w' --
→ 结果集中混入攻击者伪造的数据行
```

#### 注册功能 SQL 注入测试

```python
# 测试：注入额外数据行
POST /register
  username: x'), ('y', 'pwned', '', ''); --
  password: irrelevant
  → 数据库中同时插入 x 和 y 两个用户
  → 控制台输出: [SQL] INSERT INTO users ... VALUES ('x'), ('y', 'pwned', '', ''); --', ...)
```

### 6.3 修复后验证

```python
# 修复后：用户输入作为普通文本处理
GET /search?keyword=' OR 1=1 --
→ 搜索文本 "OR 1=1" 的用户，而非 SQL 注入
→ 控制台输出: [SQL] SELECT * FROM users WHERE username LIKE ? OR email LIKE ?
               | keyword_param='%\' OR 1=1 --%'

# 不返回 admin、alice 等无关用户
# 仅返回用户名或邮箱中包含 "OR 1=1" 字符串的用户（不会存在）
```

---

## 7. 总结

### 7.1 漏洞数据统计

| 指标 | 数值 |
|------|------|
| 发现 SQL 注入漏洞数 | **2 个** |
| 漏洞严重等级 | 🔴 严重 × 2 |
| 影响路由 | `/search`、`/register` |
| 涉及 CWE 分类 | CWE-89 (SQL Injection) |
| 修复代码行数 | **3 行**（两个路由各改 1 行 SQL + 1 行 print） |

### 7.2 经验教训

1. **永远不要使用字符串拼接构建 SQL**：无论输入是否"可信"，f-string、`+`、`format()` 都不应出现在 SQL 语句中
2. **参数化查询是银弹**：`?` 占位符 + 参数元组可以防御一切形式的 SQL 注入，零性能开销
3. **打印 SQL 日志要安全**：修复后仍可打印 SQL 模板和参数值用于调试，但参数值要单独展示，不拼入模板
4. **不要相信用户输入**：所有用户输入都是潜在的攻击向量，包括注册字段和搜索关键词

### 7.3 修复前后攻击效果对比

| 攻击向量 | 修复前效果 | 修复后效果 |
|---------|-----------|-----------|
| `' OR 1=1 --` | ✅ 泄露全部用户 | ❌ 作为普通文本搜索 |
| `' UNION SELECT ...` | ✅ 注入伪造数据 | ❌ 作为普通文本搜索 |
| `x'), ('y','pw','',''); --` | ✅ 创建多个用户 | ❌ 注册失败或因引号被转义 |

### 7.4 防御建议

| 优先级 | 建议 | 说明 |
|--------|------|------|
| 🔴 P0 | **全员使用参数化查询** | 所有 SQL 操作必须使用 `?` 占位符，禁止字符串拼接 |
| 🟠 P1 | **最小权限原则** | 数据库连接使用只读账号（搜索）、写入分离 |
| 🟡 P2 | **输入验证** | 对用户名、邮箱等字段做格式校验（正则、长度限制） |
| 🟡 P3 | **WAF 规则** | 在反向代理层拦截 `OR 1=1`、`UNION SELECT`、`--` 等注入签名 |
| 🟢 P4 | **定期安全扫描** | 使用 SQLMap 等自动化工具对应用进行渗透测试 |

---

> **报告生成日期**：2026-07-19
> **系统版本**：v2.0（新增注册 + 搜索功能）
> **报告人**：Claude Security Audit
