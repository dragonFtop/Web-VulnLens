from __future__ import annotations

import ast
import re

from app.core.extractor.candidates import Candidate
from app.core.parser.code_parser import ParsedCode

SOURCE_ATTRS = {
    "request.args",
    "request.form",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.json",
    "request.files",
    "request.GET",
    "request.POST",
    "request.body",
    "request.data",
    "request.query_params",
}
SOURCE_CALLS = {
    "request.get_json",
    "request.get_data",
}
SANITIZER_FUNCS = {
    "int",
    "float",
    "html.escape",
    "markupsafe.escape",
    "flask.escape",
    "escape",
    "shlex.quote",
}
SUBPROCESS_FUNCS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
}
WEAK_PARAM_RE = re.compile(
    r"(user_?input|payload|query|cmd|command|untrusted|user_?data|filename|url_param)",
    re.IGNORECASE,
)


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _source_label(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        if name in SOURCE_CALLS:
            return name
        if any(name == attr or name.startswith(attr + ".") for attr in SOURCE_ATTRS):
            return name
    if isinstance(node, ast.Attribute):
        name = _dotted(node)
        if name in SOURCE_ATTRS:
            return name
    if isinstance(node, ast.Subscript):
        base = node.value
        if isinstance(base, ast.Attribute):
            name = _dotted(base)
            if name in SOURCE_ATTRS:
                return name
        if isinstance(base, ast.Call):
            return _source_label(base)
    return None


def _iter_scope_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef):
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in target.elts:
            names.extend(_target_names(child))
        return names
    return []


def _origins(expr: ast.AST | None, tainted: dict[str, str]) -> set[str]:
    if expr is None:
        return set()
    label = _source_label(expr)
    if label:
        return {label}
    if isinstance(expr, ast.Name):
        origin = tainted.get(expr.id)
        return {origin} if origin else set()
    if isinstance(expr, ast.Constant):
        return set()
    if isinstance(expr, ast.Call):
        name = _dotted(expr.func)
        if name in SANITIZER_FUNCS:
            return set()
        found: set[str] = set()
        if isinstance(expr.func, ast.Attribute):
            found |= _origins(expr.func.value, tainted)
        for arg in expr.args:
            found |= _origins(arg, tainted)
        for keyword in expr.keywords:
            found |= _origins(keyword.value, tainted)
        return found
    if isinstance(expr, ast.Attribute):
        return _origins(expr.value, tainted)
    if isinstance(expr, ast.JoinedStr):
        found = set()
        for value in expr.values:
            found |= _origins(value, tainted)
        return found
    if isinstance(expr, ast.FormattedValue):
        found = _origins(expr.value, tainted)
        found |= _origins(expr.format_spec, tainted)
        return found
    if isinstance(expr, ast.BinOp):
        return _origins(expr.left, tainted) | _origins(expr.right, tainted)
    if isinstance(expr, ast.UnaryOp):
        return _origins(expr.operand, tainted)
    if isinstance(expr, ast.BoolOp):
        found = set()
        for value in expr.values:
            found |= _origins(value, tainted)
        return found
    if isinstance(expr, ast.Compare):
        found = _origins(expr.left, tainted)
        for comparator in expr.comparators:
            found |= _origins(comparator, tainted)
        return found
    if isinstance(expr, ast.IfExp):
        return (
            _origins(expr.test, tainted)
            | _origins(expr.body, tainted)
            | _origins(expr.orelse, tainted)
        )
    if isinstance(expr, ast.Subscript):
        return _origins(expr.value, tainted) | _origins(expr.slice, tainted)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        found = set()
        for element in expr.elts:
            found |= _origins(element, tainted)
        return found
    if isinstance(expr, ast.Dict):
        found = set()
        for key, value in zip(expr.keys, expr.values):
            found |= _origins(key, tainted)
            found |= _origins(value, tainted)
        return found
    if isinstance(expr, ast.Starred):
        return _origins(expr.value, tainted)
    if isinstance(expr, ast.Await):
        return _origins(expr.value, tainted)
    if isinstance(expr, ast.NamedExpr):
        return _origins(expr.value, tainted)
    return set()


def _truthy_constant(value: ast.AST | None) -> bool:
    if isinstance(value, ast.Constant):
        return bool(value.value)
    return False


class TaintAnalyzer:
    def __init__(self, parsed: ParsedCode) -> None:
        self.parsed = parsed
        self.candidates: list[Candidate] = []
        self._seen: set[tuple[str, int]] = set()
        self.parse_error: str | None = None

    def analyze(self) -> list[Candidate]:
        try:
            tree = ast.parse(self.parsed.text)
        except SyntaxError as exc:
            self.parse_error = f"Python 语法解析失败：{exc.msg}（第 {exc.lineno} 行）"
            return []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node)
        return self.candidates

    def _collect_tainted(
        self, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> dict[str, str]:
        tainted: dict[str, str] = {}
        args = list(function.args.args) + list(function.args.kwonlyargs) + list(function.args.posonlyargs)
        for arg in args:
            if WEAK_PARAM_RE.search(arg.arg):
                tainted[arg.arg] = f"函数参数 {arg.arg}（弱提示）"
        if function.args.vararg and WEAK_PARAM_RE.search(function.args.vararg.arg):
            tainted[function.args.vararg.arg] = f"可变参数 {function.args.vararg.arg}（弱提示）"

        nodes = sorted(
            (node for node in _iter_scope_nodes(function) if hasattr(node, "lineno")),
            key=lambda node: node.lineno,
        )
        for _ in range(4):
            changed = False
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    origin = _origins(value, tainted)
                    if not origin:
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for name in _target_names(target):
                            if name not in tainted:
                                tainted[name] = "/".join(sorted(origin))
                                changed = True
                elif isinstance(node, ast.AugAssign):
                    origin = _origins(node.target, tainted) | _origins(node.value, tainted)
                    for name in _target_names(node.target):
                        if name not in tainted:
                            tainted[name] = "/".join(sorted(origin))
                            changed = True
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    origin = _origins(node.iter, tainted)
                    if origin:
                        for name in _target_names(node.target):
                            if name not in tainted:
                                tainted[name] = "/".join(sorted(origin))
                                changed = True
                elif isinstance(node, ast.NamedExpr):
                    origin = _origins(node.value, tainted)
                    for name in _target_names(node.target):
                        if origin and name not in tainted:
                            tainted[name] = "/".join(sorted(origin))
                            changed = True
                elif isinstance(node, ast.comprehension):
                    continue
            if not changed:
                break
        return tainted

    def _evidence(self, start: int, end: int) -> str:
        end = max(start, end)
        chunk = "\n".join(self.parsed.lines[start - 1 : end])
        chunk = chunk.strip()
        return chunk[:1000]

    def _safe_hints(self, expr: ast.AST | None, function_text: str) -> list[str]:
        hints: list[str] = []
        expr_text = ast.unparse(expr) if expr is not None else ""
        if any(token in expr_text for token in ("ALLOWED", "allowlist", "whitelist", "WHITELIST")):
            hints.append("疑似白名单校验")
        if re.search(r"%(s|d)|:\w+|\?", expr_text):
            hints.append("SQL 含占位符标记，需确认参数是否绑定")
        for token, label in (
            ("html.escape", "html.escape 转义"),
            ("markupsafe", "markupsafe 转义"),
            ("shlex.quote", "shlex.quote 转义"),
            ("int(", "整数强制转换"),
        ):
            if token in function_text:
                hints.append(label)
        return sorted(set(hints))

    def _function_text(self, function: ast.AST) -> str:
        start = function.lineno
        end = getattr(function, "end_lineno", None) or start
        return "\n".join(self.parsed.lines[start - 1 : end])

    def _add(
        self,
        rule_id: str,
        vuln_hint: str,
        call: ast.Call,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        origins: set[str],
        dangerous_expr: ast.AST | None,
        notes: str,
    ) -> None:
        line_start = call.lineno
        line_end = getattr(call, "end_lineno", None) or line_start
        key = (rule_id, line_start)
        if key in self._seen:
            return
        self._seen.add(key)
        decorators = []
        for decorator in function.decorator_list:
            try:
                decorators.append("@" + ast.unparse(decorator))
            except Exception:
                continue
        route_note = f"；路由: {decorators[0]}" if decorators else ""
        origin_note = "/".join(sorted(origins)) or "不确定来源"
        all_notes = f"{notes}；污染来源: {origin_note}{route_note}"
        hints = self._safe_hints(dangerous_expr, self._function_text(function))
        self.candidates.append(
            Candidate(
                id="",
                vuln_hint=vuln_hint,
                language="python",
                rule_id=rule_id,
                line_start=line_start,
                line_end=line_end,
                evidence=self._evidence(line_start, line_end),
                function_name=function.name,
                safe_patterns=hints,
                notes=all_notes,
                function_line_start=function.lineno,
                function_line_end=getattr(function, "end_lineno", None) or line_start,
            )
        )

    def _analyze_function(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        tainted = self._collect_tainted(function)
        for node in _iter_scope_nodes(function):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            final = name.rsplit(".", 1)[-1]

            if final in {"execute", "executemany"} and node.args:
                sql_expr = node.args[0]
                origins = _origins(sql_expr, tainted)
                if origins:
                    self._add(
                        "SQLI-001",
                        "SQL_INJECTION",
                        node,
                        function,
                        origins,
                        sql_expr,
                        "动态构造的 SQL 进入数据库执行调用",
                    )

            if final == "render_template_string" and node.args:
                origins = _origins(node.args[0], tainted)
                if origins:
                    self._add(
                        "XSS-001",
                        "XSS",
                        node,
                        function,
                        origins,
                        node.args[0],
                        "用户可控内容作为 Jinja2 模板源码渲染",
                    )

            if final == "Markup" and node.args:
                origins = _origins(node.args[0], tainted)
                if origins:
                    self._add(
                        "XSS-001",
                        "XSS",
                        node,
                        function,
                        origins,
                        node.args[0],
                        "用户内容被标记为安全 HTML（Markup）",
                    )

            if final in {"Response", "make_response"} and node.args:
                mimetype = "text/html"
                for keyword in node.keywords:
                    if keyword.arg in {"mimetype", "content_type"} and isinstance(
                        keyword.value, ast.Constant
                    ):
                        mimetype = str(keyword.value.value)
                origins = _origins(node.args[0], tainted)
                if origins and "html" in mimetype.lower():
                    self._add(
                        "XSS-001",
                        "XSS",
                        node,
                        function,
                        origins,
                        node.args[0],
                        "用户可控内容未转义进入 HTML 响应",
                    )

            if name in {"os.system", "os.popen"} and node.args:
                origins = _origins(node.args[0], tainted)
                if origins:
                    self._add(
                        "RCE-001",
                        "COMMAND_INJECTION",
                        node,
                        function,
                        origins,
                        node.args[0],
                        "用户可控数据进入 shell 命令执行",
                    )

            if name in SUBPROCESS_FUNCS:
                shell_true = False
                for keyword in node.keywords:
                    if keyword.arg == "shell" and _truthy_constant(keyword.value):
                        shell_true = True
                if shell_true:
                    origins: set[str] = set()
                    for arg in node.args:
                        origins |= _origins(arg, tainted)
                    for keyword in node.keywords:
                        if keyword.arg != "shell":
                            origins |= _origins(keyword.value, tainted)
                    if origins:
                        self._add(
                            "RCE-001",
                            "COMMAND_INJECTION",
                            node,
                            function,
                            origins,
                            node.args[0] if node.args else None,
                            "subprocess 以 shell=True 执行用户可控命令",
                        )

            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"} and node.args:
                origins = _origins(node.args[0], tainted)
                if origins:
                    self._add(
                        "RCE-002",
                        "COMMAND_INJECTION",
                        node,
                        function,
                        origins,
                        node.args[0],
                        f"用户可控数据进入 {node.func.id}() 动态代码执行",
                    )


def extract_python_candidates(parsed: ParsedCode) -> tuple[list[Candidate], str | None]:
    analyzer = TaintAnalyzer(parsed)
    candidates = analyzer.analyze()
    return candidates, analyzer.parse_error
