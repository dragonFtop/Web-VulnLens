<div align="center">

# Web VulnLens

**基于 LLM 的 Web 代码漏洞智能检测与修复工具**

规则 · AST 污点分析 · BM25 知识检索 · 大模型结构化判定，组成混合静态代码审计工作台

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
![Tests](https://img.shields.io/badge/tests-98%20passed-brightgreen)
![LLM](https://img.shields.io/badge/LLM-DeepSeek%20%7C%20OpenAI%20compatible-4B32C3)

[简体中文](README.md) · [English](README.en.md)

</div>

![Web VulnLens 工作台](docs/screenshots/home.webp)

> **四川大学网络空间安全技术课程设计。** 系统面向单个 Web 源文件（`.py` / `.php` / `.js`）或一段原始 HTTP 请求，检测 SQL 注入、XSS 与命令执行，输出证据、定级、修复建议、补丁与验证结果。
>
> **授权提醒：** 仅用于自有代码或已获得明确授权的材料。静态分析与 LLM 结论不构成安全保证；HTTP 分析完全被动，不会向目标发送任何请求；修复补丁上线前必须由人工复核。

## 特性

**检测**

- **混合候选提取**：Python 使用 AST 污点分析跟踪 `source → sanitizer → sink`；PHP / JS 使用带上下文窗口的规则匹配；HTTP 在解码后的参数值上匹配。
- **三通道结果**：`both`（规则与 LLM 互证）、`llm`（模型补漏）、`rule`（待复核线索，不计入确认漏洞），避免把单侧命中当成结论。
- **两阶段知识检索**：BM25 先按“漏洞类型 + 语言”召回，不足时回退到通用知识；知识编号严格回验，模型不能引用未检索到的条目。
- **HTTP 参数级定位**：URL / HTML 实体 / Unicode / Base64 多重解码，结果定位到 `query.host`、`body.username` 等具体参数位置。

**可靠性与安全**

- **证据回验**：模型给出的证据必须能在对应代码行或参数值中逐字找到，否则该条结果被丢弃。
- **提示注入防御**：指令层级隔离、nonce 数据定界、代码围栏中和、中英文可疑短语检测、证据回验，命中可疑内容时可选独立复核。
- **输出校验**：JSON Schema 校验 + 自动纠错；不可用输出降级为规则候选结果并显式标注，不会静默展示。
- **密钥不落地**：API Key 只从环境变量读取，不写入数据库、日志或前端。

**修复与工程化**

- **修复闭环**：生成完整补丁 → Python `ast.parse` 语法检查 → 规则复扫 → 可选 LLM 复核；补丁独立保存，不覆盖原文件、不自动部署。
- **完整工作台**：任务轮询、源码高亮、证据卡片、历史检索、HTML / JSON 报告导出；前端资源全部本地 vendored，不依赖 CDN。
- **可复现评测**：A/B/C/D 四组消融实验，输出 P/R/F1、硬负例误报率、JSON 合法率、注入抵御率、token 与时延，结果保存为 JSON 与 Markdown。

## 界面预览

> 截图由 `deepseek-chat` 对仓库内 `samples/` 样本真实扫描生成（2026-10-30），未使用设计稿或伪造数据。界面语言为中文。

### 代码扫描：证据、定级与知识依据

![SQL 注入扫描结果](docs/screenshots/scan-result.webp)

SQL 注入样本被规则与模型双通道确认：页面展示置信度、CWE 编号、证据行、修复建议与 BM25 知识引用，并区分高危、中危、低危与待复核线索。

### 源码视图：三通道行高亮

![源码高亮视图](docs/screenshots/code-view.webp)

源码中的命中行按 `both` / `llm` / `rule` / 疑似注入着色；点击行号可跳转到对应漏洞卡片。

### 修复闭环：Diff 与三重验证

![修复验证](docs/screenshots/repair.webp)

![修复 Diff](docs/screenshots/repair-diff.webp)

修复页展示语法检查、复扫、LLM 复核与综合验证结果，以及完整 diff。补丁文件通过独立链接下载，原文件保持不变。

### HTTP 请求分析：参数级定位与解码链

![HTTP 请求分析结果](docs/screenshots/http-result.webp)

![HTTP 参数解码链](docs/screenshots/http-decode.webp)

系统只解析请求文本，不连接 Host。参数值逐层解码后，按漏洞类型与参数位置给出结论。

### 提示注入防御

![提示注入防御](docs/screenshots/prompt-injection.webp)

样本中伪造的 `[SYSTEM]` 指令被识别并隔离展示，不会进入系统指令层级；该样本本身没有真实漏洞，最终确认漏洞为 0 条。

### 规则线索：单侧命中不冒充漏洞

![规则线索](docs/screenshots/rule-clue.webp)

规则命中但模型未确认时，结果以“待复核线索”单独展示，不计入确认漏洞，也不提供自动修复。

### 历史记录与报告导出

![历史扫描记录](docs/screenshots/history.webp)

历史页支持按状态筛选；详情页可导出 HTML 或 JSON 报告，报告包含模型与提示词版本、配置快照、免责声明和逐条结果。

## 工作原理

```mermaid
flowchart LR
    A["代码文件 / 原始 HTTP 请求"] --> B["解析与编码识别"]
    B --> C["候选提取<br/>AST 污点分析 / 规则"]
    C --> D["BM25 知识检索"]
    D --> E["LLM 结构化判定"]
    E --> F["证据回验 + 三通道合并"]
    F --> G["漏洞报告 / HTML 与 JSON 导出"]
    F -.->|用户请求修复| H["修复闭环"]
    H --> I["补丁生成 → 语法检查 → 复扫 → 可选 LLM 复核"]
    I --> J["补丁文件（不覆盖原文件）"]
```

1. **解析与编码识别**：识别语言与文件编码，提取 HTTP 请求行、请求头、参数与 Body。
2. **候选提取**：Python AST 跟踪从输入源到危险函数的传播链；PHP / JS 与 HTTP 使用规则匹配，并截取上下文窗口。
3. **知识检索**：BM25 按漏洞类型与语言召回修复知识，随候选窗口一并送入模型。
4. **模型判定**：模型只在候选窗口内给出结构化 JSON 结论；证据必须能在原文中回验。
5. **合并与展示**：规则与模型结果按位置合并，人工复核线索单独展示；可继续生成补丁并验证。

### 三通道含义

| 通道 | 含义 | 是否计入确认漏洞 | 置信度基准 |
|---|---|---|---|
| `both` | 规则与 LLM 在同一位置、同一类型互相印证 | 是 | 0.90 |
| `llm` | 模型在候选窗口内补充发现 | 是 | 0.60 |
| `rule` | 规则命中但未获模型确认 | 否，展示为待复核线索 | 0.35 |

置信度会结合证据回验与模型自评微调，最终限制在 `0.30–0.99`。

## 快速开始

### 环境要求

- Python 3.10+（本项目在 Python 3.14 上验证）
- 无需 Docker、数据库服务或前端构建工具
- 一个 OpenAI Chat Completions 兼容的模型服务；默认使用 DeepSeek `deepseek-chat`

### 安装与启动

```bash
git clone <仓库地址>
cd Web-VulnLens

python -m venv .venv
source .venv/Scripts/activate          # Windows Git Bash
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env                    # 填入真实的 LLM_API_KEY
python scripts/init_db.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

浏览器访问 <http://127.0.0.1:8000>，接口文档为 <http://127.0.0.1:8000/docs>。

> 若端口 8000 被占用，可改用 `--port 8001`。若终端中的 `python` 是 Windows Store 占位程序（退出码 49），请始终使用 `.venv/Scripts/python.exe`。

### 配置

复制 `.env.example` 为 `.env` 后，至少填写：

```dotenv
LLM_API_KEY=你的密钥
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat
```

其他常用配置：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `LLM_TEMPERATURE` | `0.1` | 检测与修复温度 |
| `LLM_TIMEOUT` | `60` | 单次模型调用超时（秒） |
| `LLM_MAX_RETRIES` | `2` | 网络错误 / 429 / 5xx 重试次数 |
| `LLM_JSON_MODE` | `true` | 使用 OpenAI 兼容 JSON 模式 |
| `MAX_UPLOAD_MB` | `1` | 上传文件大小上限 |
| `MAX_HTTP_BODY_KB` | `256` | HTTP 请求 body 上限 |
| `MAX_LLM_CODE_CHARS` | `24000` | 送入模型的代码字符上限 |
| `MAX_CANDIDATES` | `20` | 单次扫描候选上限 |
| `KB_TOP_K` | `3` | 每类知识召回首数 |
| `REPAIR_ENABLED` | `true` | 是否开放修复接口 |
| `REPAIR_MAX_FILE_KB` | `100` | 可自动修复的文件上限 |
| `REPAIR_VERIFY_LLM` | `true` | 修复后是否追加 LLM 复核 |
| `DEMO_CACHE` | `true` | 是否启用演示缓存 |
| `GUARD_RECHECK` | `true` | 发现可疑内容时是否独立复核 |
| `DB_PATH` | `storage/app.db` | SQLite 数据库路径 |
| `LOG_LEVEL` | `INFO` | 日志级别 |

任何 OpenAI Chat Completions 兼容服务均可通过 `LLM_BASE_URL` / `LLM_MODEL` 接入（包括本地推理服务），稳定性需自行验证。API Key 只从环境变量读取，不写入数据库、日志或前端。

没有密钥时，只有命中 `storage/cache/` 的演示缓存才能返回结果，否则任务以 `E_LLM_AUTH` 失败。

### 演示缓存

预先用样本跑一遍扫描填充 `storage/cache/`，答辩或演示时保持 `DEMO_CACHE=true`，即使断网也能回放相同请求的结果，页面会标注“缓存回放”。切换模型或提示词版本后建议清空缓存，避免新旧结果混用。

## 使用流程

1. 在首页选择“代码文件”，上传 `.py` / `.php` / `.js` 文件；或切换到“原始 HTTP 请求”，粘贴 HTTP/1.1 原始请求。
2. 任务在后台执行，页面轮询解析、候选提取、知识检索、模型分析等阶段。
3. 结果页展示确认漏洞、规则线索、可疑提示注入内容、证据行、知识引用与置信度。
4. 对代码类确认漏洞点击“生成修复”，查看 diff 与“语法通过 / 复扫干净 / LLM 复核”状态，下载补丁文件。
5. 在历史页检索任务，导出 HTML 或 JSON 报告。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/upload` | 上传 `.py` / `.php` / `.js`，返回 `file_id` |
| `POST` | `/api/scans` | 创建扫描任务：代码传 `file_id`，HTTP 传 `raw_http` |
| `GET` | `/api/scans` | 历史任务分页，支持 `page` / `per_page` / `status` |
| `GET` | `/api/scans/{job_id}` | 任务状态、阶段与统计 |
| `GET` | `/api/scans/{job_id}/findings` | 漏洞、线索、可疑内容与汇总 |
| `POST` | `/api/findings/{finding_id}/repair` | 生成修复补丁并执行验证 |
| `GET` | `/api/repairs/{repair_id}` | 修复详情（diff、验证状态） |
| `GET` | `/api/repairs/{repair_id}/download` | 下载补丁文件 |
| `GET` | `/api/scans/{job_id}/report?format=html\|json` | 导出报告 |
| `GET` | `/docs` | Swagger UI |

```bash
# 1. 上传文件，记下返回的 file_id
curl -s -F "file=@samples/code/sql_injection/vuln_01.py" \
  http://127.0.0.1:8000/api/upload

# 2. 创建扫描任务，记下返回的 job_id
curl -s -H "Content-Type: application/json" \
  -d '{"input_type":"code","file_id":"<file_id>"}' \
  http://127.0.0.1:8000/api/scans

# 3. 轮询任务，完成后获取结果
curl -s http://127.0.0.1:8000/api/scans/<job_id>/findings
```

## 检测与合并

- **候选来源**：Python AST 跟踪 source → sanitizer → sink；PHP / JS 使用带 ±8 行窗口的规则；HTTP 在解码后的参数值上匹配规则。
- **候选上下文**：函数范围（≤120 行）或目标行 ±15 行，单块最多 60 行，最多 20 个候选。
- **合并匹配**：优先按 `candidate_id`，否则同类型行区间重叠或行差 ≤2；HTTP 按漏洞类型 + 参数位置匹配。
- **定级**：`COMMAND_INJECTION` / `SQL_INJECTION` 基准 3，`XSS` 基准 2，再按输入可控、认证、净化因子调整。
- **证据回验**：模型给出的证据必须能在对应代码行或参数值中逐字找到，否则丢弃该条结果。
- **降级策略**：JSON 解析失败先自动纠错一次；仍失败或 Schema 无效时，降级为规则候选结果并显式标注。
- **提示注入防御**：系统指令与待分析数据分层，nonce 定界数据区，中和三反引号，检测中英文可疑短语（如“忽略以上指令”“mark as secure”），命中可疑内容时可将清洗后的上下文交给模型独立复核。

## 测试

```bash
python -m pytest -q
```

当前 **98 项测试全部通过**，覆盖：

- 编码识别、上传安全、大小限制与路径穿越
- HTTP 解析与 URL / HTML / Unicode / Base64 多重解码
- Python AST 正例与硬负例、PHP / JS 规则
- Guard 中英文注入检测与无指令文本
- JSON Schema 校验、合并定级、知识检索与回验
- 修复、语法检查、复扫、报告转义与安全响应头
- 完整 API 流程与评测匹配逻辑

## 消融评测

评测脚本直接调用真实模型，会产生 API 费用。默认禁用缓存，建议先在 `.env` 中配置密钥。

```bash
python scripts/eval.py --no-cache
```

四组配置：

| 组 | 路线 |
|---|---|
| A | 整文件直接问 LLM，无候选 / 知识 / 防御 |
| B | 候选窗口 + LLM |
| C | B + BM25 知识检索 |
| D | C + 提示注入防御 |

默认 A–D 都评测 30 条代码样本（15 个漏洞 + 15 个安全硬负例）与 10 条 HTTP 样本，仅 D 额外评测 8 条提示注入样本。常用参数：

```bash
# 只跑 D 组做冒烟
python scripts/eval.py --groups D --limit 2 --no-cache

# 注入防御前后对比（A、D 都运行注入样本）
python scripts/eval.py --groups A,D --only injection --injection-groups A,D --no-cache

# 断网回放已有演示缓存
python scripts/eval.py --cache
```

输出默认保存为 `storage/reports/eval_<时间戳>.json` 和 `.md`，包含汇总表、TP/FP/FN、规则线索数、JSON 纠错 / 失败数、token、时延和逐样本简要结果。评测口径：

- 仅 `both` / `llm` 计入确认漏洞，`rule` 线索单独统计。
- 代码样本同类型且行区间重叠或行差 ≤2 视为命中；HTTP 样本按类型 + 参数位置命中。
- 硬负例误报率按 15 条代码安全样本统计；JSON 合法率按最终可用结构统计，包含降级和顶层 Schema 无效。
- 注入抵御成功要求：标记可疑内容、真实漏洞仍被检出、未被诱导产生额外误报。
- 固定同一模型、温度、提示词版本和样本集；单次运行仅作课程实验参考，建议重复 2–3 次并注明波动。

## 项目结构

```text
app/
  api/                上传、扫描、历史、修复、报告接口
  core/
    extractor/        Python AST 污点分析、PHP/JS 规则、候选上下文
    knowledge/        BM25 知识库与两级检索
    llm/              OpenAI 兼容客户端、提示词、Guard、Schema 校验
    parser/           编码 / 语言识别、代码解析、HTTP 解析与解码链
    repair/           补丁生成、diff、语法检查、复扫与复核
  db/                 SQLite schema 与参数化仓储
  services/           扫描编排、结果合并 / 定级、修复服务
  web/                Jinja2 模板、静态 JS/CSS、本地 vendor
scripts/
  init_db.py          初始化数据库
  eval.py             A/B/C/D 消融评测
samples/
  code/               30 条代码样本（15 个漏洞 + 15 个安全硬负例）
  http/               10 条 HTTP 请求样本
  injection/          8 条提示注入样本
tests/                pytest 单元与接口测试
docs/screenshots/     README 截图
storage/              运行时数据（数据库、上传、缓存、补丁、报告）

requirements.txt      Python 依赖
.env.example          环境变量模板
```

## 安全边界

- 不执行被检测代码；语法校验仅使用 Python `ast.parse`。
- 补丁只写入 `storage/patched/`，永不覆盖原文件、永不自动部署。
- 上传白名单、大小限制、服务端随机文件名、路径校验、空字节 / 二进制拒绝。
- HTTP 分析完全被动，不构造或发送攻击请求。
- 所有数据库访问参数化；Jinja2 自动转义；代码高亮使用文本模式，不向 `innerHTML` 注入原始代码。
- 默认绑定 `127.0.0.1`，CSP、`X-Content-Type-Options`、`X-Frame-Options` 等响应头已启用。
- 模型输出先解析校验再展示；密钥不落库、不进日志、不返回前端。

## 范围与局限

- 只支持单文件、三种语言、三类漏洞；没有跨文件污点追踪、依赖漏洞、业务逻辑漏洞和运行时配置分析。
- 不做动态沙箱验证，不证明漏洞可利用性；HTTP 结果只说明请求含可疑载荷，不代表目标站点存在漏洞。
- PHP / JS 只做规则与语法层面的启发式分析，修复补丁需要人工确认。
- LLM 存在不确定性，可能漏报或误报；提示注入防御降低风险，但不宣称 100% 防御。
- 单用户本地工具，未实现权限、分布式队列、云端部署和 CSRF 防护；不要直接暴露到公网。

## 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| 启动报需要 API Key | 未配置密钥且未开启演示缓存 | 填写 `.env` 或设置 `DEMO_CACHE=true` |
| 扫描失败 `E_LLM_AUTH` | 密钥错误或额度不足 | 检查 `LLM_API_KEY` 与账户 |
| `E_LLM_TIMEOUT` | 网络或模型响应慢 | 重试、调大 `LLM_TIMEOUT` 或切换本地模型 |
| `E_LLM_JSON` | 模型未按 JSON 输出且纠错失败 | 系统已降级为规则线索；检查提示词 / 模型 |
| 上传 400 / 413 | 类型、编码或大小不合规 | 转为 UTF-8、检查后缀与大小 |
| 页面中文乱码 | 源文件编码异常 | 系统会尝试 UTF-8 / GBK；仍失败请转换编码 |
| 端口被占用 | 8000 已被使用 | 换 `--port 8001` |

## 重置数据

停止服务后清空 `storage/`，再执行 `python scripts/init_db.py`。切换模型或提示词版本后建议清空 `storage/cache/`，避免新旧结果混用。

## 声明

本项目为四川大学网络空间安全技术课程设计，仅用于学习、研究与已获授权的安全测试。仓库暂未附带开源许可证（LICENSE）；如需引用或复用，请先与作者联系。
