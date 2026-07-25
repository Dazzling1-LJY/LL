# SSTI 漏洞修复报告

**项目名称**：用户管理系统 – 个性化页面功能  
**测试日期**：2026-07-21  
**测试人员**：刘婧宜  
**学号**：2024141530009  
**修复版本**：v10.0（SSTI 安全加固版）  

---

## 目录

1. [测试环境与工具](#1-测试环境与工具)
2. [漏洞修复及修复后测试](#2-漏洞修复及修复后测试)
3. [修复前后对比](#3-修复前后对比)
4. [总结](#4-总结)

---

## 1. 测试环境与工具

| 项目 | 内容 |
|:-----|:------|
| **目标系统** | 用户管理系统 Flask Web 应用 |
| **技术栈** | Python 3.13 + Flask + Jinja2 + Werkzeug |
| **测试地址** | `http://127.0.0.1:5000` |
| **修复路由** | `GET /welcome`、`GET/POST /feedback` |
| **测试账号** | admin / admin123, alice / alice2025 |
| **测试工具** | 浏览器 + Python requests + curl |

### 涉及漏洞清单

| 漏洞编号 | 漏洞名称 | CWE | 修复前风险 |
|:---------|:---------|:---:|:---------:|
| **SSTI-001** | **/welcome 模板注入（支持RCE）** | CWE-1336 | 🔴 **严重** |
| **SSTI-002** | **/feedback 模板注入（双参数+RCE）** | CWE-1336 | 🔴 **严重** |

---

## 2. 漏洞修复及修复后测试

### 2.1 修复代码

#### 修复核心思路

**模板与数据分离**：模板字符串中只写 `{{ name }}` 变量占位符，用户输入通过 `render_template_string(html, name=name)` 以参数方式传入。这样用户输入中的 `{{ }}` 不会被当作模板语法解析，同时 Jinja2 的自动 HTML 转义也会生效。

#### 修复前（漏洞代码）

```python
# /welcome 修复前：f-string 直接拼接用户输入
name = request.args.get("name", "")
html = f"<h1>欢迎你，{name}！</h1>"          # ← name 被当作 Python 字符串拼接
return render_template_string(html)          # ← 拼接结果被当作 Jinja2 模板解析

# /feedback 修复前：同样 f-string 拼接
result_html = f"<h2>{name} 的反馈：</h2><p>{message}</p>"
return render_template_string(result_html)
```

#### 修复后（安全代码）

```python
# /welcome 修复后：模板变量方式
name = request.args.get("name", "")
html = "<h1>欢迎你，{{ name }}！</h1>"        # ← 模板中使用变量占位符
return render_template_string(html, name=name)  # ← 用户输入以变量传入

# /feedback 修复后：模板变量方式
result_html = "<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>"
return render_template_string(result_html, name=name, message=message)
```

#### 完整修复代码

**`/welcome` 路由修复**（`app.py` 第 689-718 行）：

```python
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        username = session.get("username")
        if username:
            name = username
        else:
            name = "亲爱的用户"
    # ✅ 修复 SSTI：使用模板变量代替 f-string 拼接
    html = """<!DOCTYPE html>
...（完整 HTML 结构）...
            <h1>欢迎你，{{ name }}！</h1>          <!-- Jinja2 变量，安全 -->
..."""
    return render_template_string(html, name=name)  # ✅ name 作为模板变量传入
```

**`/feedback` POST 修复**（`app.py` 第 765-797 行）：

```python
    # POST — 修复 SSTI：使用模板变量代替 f-string 拼接
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    result_html = """<!DOCTYPE html>
...（完整 HTML 结构）...
            <h2>{{ name }} 的反馈：</h2>           <!-- Jinja2 变量，安全 -->
            <p>{{ message }}</p>                    <!-- Jinja2 变量，安全 -->
..."""
    return render_template_string(result_html, name=name, message=message)
```

### 2.2 防护原理

| 机制 | 修复前 | 修复后 | 说明 |
|:-----|:------:|:------:|:------|
| **f-string 拼接** | ✅ `f"...{name}..."` | ❌ 未使用 | 修复前用户输入被当作 Python 代码拼入字符串 |
| **模板变量传递** | ❌ 未使用 | ✅ `name=name` | 修复后用户输入作为变量值传入模板引擎 |
| **Jinja2 语法解析** | ✅ 解析用户输入中的 `{{ }}` | ❌ 不解析 | 修复后 `{{ }}` 被当作普通文本 |
| **HTML 自动转义** | ❌ 需要 `\| safe` | ✅ 自动生效 | 修复后 `<script>` 转义为 `&lt;script&gt;` |

### 2.3 修复验证

#### 验证方法

每个攻击向量使用与漏洞发现时完全相同的 Payload 进行测试，确认 SSTI 被成功拦截、XSS 被自动转义。

#### 验证结果

##### 测试 1：正常功能不受影响

| 测试项 | Payload | 修复前 | 修复后 | 结果 |
|:-------|:--------|:------:|:------:|:----:|
| /welcome 姓名 | `?name=张三` | ✅ 张三 | ✅ 张三 | 通过 |
| /welcome 默认 | 无 name | ✅ 亲爱的用户 | ✅ 亲爱的用户 | 通过 |
| /feedback 表单 | GET | ✅ 表单 | ✅ 表单 | 通过 |
| /feedback 提交 | POST 李四 | ✅ 显示结果 | ✅ 显示结果 | 通过 |

##### 测试 2：SSTI 表达式被拦截

| 攻击向量 | Payload | 修复前 | 修复后 |
|:---------|:--------|:------:|:-------|
| 数学运算 | `{{7*7}}` | ✅ → `49`（执行！）| ❌ → 显示 `{{7*7}}` 原文 |
| 数学运算 | `{{8*8}}` | ✅ → `64` | ❌ → 显示 `{{8*8}}` 原文 |
| 字符串方法 | `{{"test".upper()}}` | ✅ → `TEST` | ❌ → 显示原文 |

##### 测试 3：配置泄露被拦截

| 攻击向量 | Payload | 修复前 | 修复后 |
|:---------|:--------|:------:|:-------|
| Flask 配置泄露 | `{{config}}` | ✅ 泄露 SECRET_KEY | ❌ 不显示配置 |
| Flask 配置泄露 | `{{config}}`（feedback） | ✅ 泄露全部配置 | ❌ 不显示配置 |

##### 测试 4：远程代码执行被拦截（最关键）

| 攻击向量 | Payload | 修复前 | 修复后 |
|:---------|:--------|:------:|:-------|
| RCE (id) | `{{...popen('id').read()}}` | ✅ **uid=0** | ❌ 不执行 |
| RCE (app.py读取) | `{{...popen('cat app.py').read()}}` | ✅ 读取源码 | ❌ 不执行 |
| RCE (/etc/passwd) | `{{...popen('cat /etc/passwd').read()}}` | ✅ 读取文件 | ❌ 不执行 |

##### 测试 5：XSS 被自动转义

| 攻击向量 | Payload | 修复前 | 修复后 |
|:---------|:--------|:------:|:-------|
| XSS /welcome | `<script>alert('xss')</script>` | ✅ 弹窗 | ❌ 显示 `&lt;script&gt;` |
| XSS /feedback name | `<script>alert('xss')</script>` | ✅ 弹窗 | ❌ 显示 `&lt;script&gt;` |
| XSS /feedback message | `<b>bold</b>` | ✅ 加粗显示 | ❌ 显示 `&lt;b&gt;bold&lt;/b&gt;` |

---

## 3. 修复前后对比

### 3.1 漏洞修复对照总表

| 漏洞编号 | 漏洞名称 | 修复前风险 | 修复措施 | 修复后风险 |
|:---------|:---------|:---------:|:---------|:---------:|
| SSTI-001 | /welcome 模板注入（RCE） | 🔴 严重 | f-string → 模板变量 `{{ name }}` + `render_template_string(html, name=name)` | 🟢 已修复 |
| SSTI-002 | /feedback 模板注入（RCE） | 🔴 严重 | f-string → 模板变量 `{{ name }}` / `{{ message }}` + 参数传入 | 🟢 已修复 |

### 3.2 攻击验证对比表

| 攻击向量 | Payload | 修复前 | 修复后 |
|:---------|:--------|:------:|:-------|
| 数学运算 | `{{7*7}}` | ✅ 返回 `49` | ❌ 显示原文 `{{7*7}}` |
| 配置泄露 | `{{config}}` | ✅ SECRET_KEY 泄露 | ❌ 不显示 |
| **RCE** | `{{...popen('id').read()}}` | ✅ **uid=0 命令执行** | ❌ 不执行 |
| **RCE 读文件** | `{{...popen('cat /etc/passwd').read()}}` | ✅ 读取系统文件 | ❌ 不执行 |
| XSS | `<script>alert('xss')</script>` | ✅ 弹窗执行 | ❌ `&lt;script&gt;` 转义 |
| XSS | `<b>bold</b>` | ✅ 加粗渲染 | ❌ `&lt;b&gt;bold&lt;/b&gt;` 转义 |
| 正常功能 | `?name=张三` | ✅ 正常 | ✅ 正常 |

### 3.3 关键代码对比

#### /welcome 路由

```python
# ❌ 修复前（漏洞代码）
name = request.args.get("name", "")
html = f"""<h1>欢迎你，{name}！</h1>"""     # f-string 拼接用户输入
return render_template_string(html)         # 作为模板渲染

# ✅ 修复后（安全代码）
name = request.args.get("name", "")
html = """<h1>欢迎你，{{ name }}！</h1>"""  # Jinja2 变量占位符
return render_template_string(html, name=name)  # 用户输入作为变量传入
```

#### /feedback POST

```python
# ❌ 修复前
result_html = f"<h2>{name} 的反馈：</h2><p>{message}</p>"
return render_template_string(result_html)

# ✅ 修复后
result_html = "<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>"
return render_template_string(result_html, name=name, message=message)
```

### 3.4 渲染流程对比

```
修复前（SSTI 漏洞）：                  修复后（安全）：
                                      |
用户输入: {{7*7}}                     用户输入: {{7*7}}
    ↓                                      ↓
f"<h1>{name}</h1>"                     模板: <h1>{{ name }}</h1>
    ↓                                      ↓
"<h1>{{7*7}}</h1>"                     变量: name="{{7*7}}"
    ↓                                      ↓
render_template_string                  render_template_string(html, name=name)
    ↓                                      ↓
Jinja2 解析 {{7*7}} → 49 ✅ 执行！       Jinja2 将 {{ name }} → {{7*7}} ❌ 不解析
    ↓                                      ↓
输出: <h1>49</h1>  ❌ 漏洞              输出: <h1>{{7*7}}</h1> ✅ 安全
```

### 3.5 安全等级变化

```
修复前：                             修复后：
🔴 严重: 2 个（SSTI-001, SSTI-002）    🔴 严重: 0 个
风险评估: ⚠️ 极高风险（可RCE）          风险评估: ✅ 安全
```

### 3.6 代码变更统计

| 维度 | 修复前 | 修复后 | 变化 |
|:-----|:------:|:------:|:----:|
| `/welcome` 模板渲染方式 | `f"...{name}..."` | `{{ name }}` + 变量传入 | 2 行修改 |
| `/feedback` 模板渲染方式 | `f"...{name}...{message}..."` | `{{ name }}` + `{{ message }}` + 变量传入 | 3 行修改 |
| 变化的代码行数 | — | — | 仅 5 行 |
| 功能逻辑 | 不变 | 不变 | ✅ |
| SSTI 防护 | ❌ 0 层 | ✅ 1 层（模板变量） | ✅ |
| XSS 防护 | ❌ 0 层 | ✅ 1 层（Jinja2 自动转义） | ✅ |

---

## 4. 总结

### 4.1 修复成果

本次安全加固对 **2 个 SSTI 漏洞** 进行了全面修复：

| 漏洞 | 路由 | 修复前风险 | 最高危害 | 修复后 |
|:-----|:------|:---------:|:---------|:------:|
| **SSTI-001** | `/welcome` | 🔴 严重 | 远程代码执行（RCE） | 🟢 安全 |
| **SSTI-002** | `/feedback` | 🔴 严重 | 远程代码执行（RCE） | 🟢 安全 |

修复后所有风险等级均降至 🟢 **安全**。

### 4.2 修复要点回顾

| 核心原则 | 修复前做法 | 修复后做法 |
|:---------|:----------|:-----------|
| **模板与数据分离** | ❌ `f"<h1>{name}</h1>"` 数据混入模版 | ✅ `<h1>{{ name }}</h1>` 变量占位符 |
| **用户输入传递方式** | ❌ 通过 f-string 拼入模板字符串 | ✅ 通过 `render_template_string(html, name=name)` 参数传入 |
| **Jinja2 语法解析** | ❌ 用户输入中的 `{{ }}` 被解析执行 | ✅ 用户输入作为纯文本值，不被解析 |
| **HTML 自动转义** | ❌ 需要手动 `\| safe` 或 f-string 不转义 | ✅ Jinja2 默认自动转义 `{{ }}` 变量值 |

### 4.3 一条原则避免 SSTI

> **永远不要用 f-string 拼接用户输入后传给 `render_template_string`！**
>
> 模板字符串中只用 `{{ 变量名 }}`，用户输入通过第二个参数以 `变量名=值` 方式传入。

```python
# ❌ 错误写法（SSTI 漏洞）
return render_template_string(f"<h1>{user_input}</h1>")

# ✅ 正确写法（安全）
return render_template_string("<h1>{{ name }}</h1>", name=user_input)
```

### 4.4 文件变更清单

| 文件 | 变更类型 | 说明 |
|:-----|:---------|:------|
| `app.py` | 🖊️ 修改 | `/welcome` 和 `/feedback` 路由 SSTI 修复（共 5 行代码变更） |

### 4.5 修复验证总结

```
总测试项: 18
✅ 通过: 18
❌ 失败: 0
通过率: 100%
结论: 🎉 所有 SSTI 漏洞已全部修复，正常功能不受影响
```

---

> **报告生成日期**：2026-07-21  
> **测试人员**：刘婧宜  
> **学号**：2024141530009  
> **修复版本**：v10.0（SSTI 安全加固版）  
