"""LLM Explainer - IDA Pro 9.2 plugin.

Asks a locally-running llama.cpp server (llama-server, OpenAI-compatible API)
to explain the function currently under the cursor, in either the Hex-Rays
pseudocode view or the plain disassembly view. The model's streamed answer
is shown in a small, non-modal dialog where you can Accept it (written into
the function's comment, visible in both views), ask to Reason More (send a
follow-up question and get a refined answer), or Cancel (discard, no
database changes).

Two settings help the model reason about code that calls into other
functions: "Follow calls depth" eagerly includes the code of called
functions (up to N levels) in the initial prompt, and independently of
that, the model can ask for a specific called function's code on demand
mid-conversation (it replies with a `REQUEST_CODE: <name-or-address>`
line, the plugin fetches that function and feeds the code back
automatically, up to "Max on-demand code requests" times).

Install by copying this single file into one of:
  - Per-user (recommended, no admin rights needed):
        <IDA user dir>\\plugins\\llm_explainer.py
    On Windows this is typically:
        %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\llm_explainer.py
  - Global (all users of this IDA install):
        <IDA install dir>\\plugins\\llm_explainer.py

Requires: IDA Pro 9.2+ (PySide6 is bundled with IDA, no extra install
needed), and a running llama.cpp `llama-server` reachable at the configured
base URL (default http://127.0.0.1:8080). The Hex-Rays decompiler is
optional - if it is not available for the current architecture the plugin
falls back to a plain disassembly listing automatically.

Configure the server URL, model, and other options via
Edit > Plugins > LLM Explainer.

Note: if llama-server is run with a single inference slot, opening several
"explain" dialogs at once will simply queue their requests on the server -
that is a server/deployment concern, not a bug in this plugin.
"""

import functools
import json
import os
import re
import threading
import urllib.error
import urllib.request
from collections import namedtuple

import idaapi
import idautils
import idc
import ida_kernwin
import ida_funcs
import ida_lines
import ida_name

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

try:
    import ida_ida
except ImportError:
    ida_ida = None

from PySide6 import QtCore, QtGui, QtWidgets


PLUGIN_NAME = "LLM Explainer"
PLUGIN_VERSION = "1.0.0"
ACTION_ID_EXPLAIN = "llm_explainer:explain_function"
CONFIG_FILENAME = "llm_explainer.cfg.json"

DEFAULT_SYSTEM_PROMPT = (
    "You are an expert reverse engineer assisting inside IDA Pro. You will "
    "be given the decompiled pseudocode or disassembly of a target function, "
    "along with its name, address, target architecture, the names of "
    "functions it calls, and - depending on settings - the code of some "
    "called functions already included below the target function.\n\n"
    "If understanding the target function requires seeing the code of a "
    "called function that was NOT already included, you may request it: "
    "reply with one or more lines of the exact form\n"
    "REQUEST_CODE: <function name or address>\n"
    "and nothing else in that reply. You will then be given that function's "
    "code in a follow-up message and can continue reasoning. Only request "
    "functions that are actually relevant, and never request the same "
    "function twice.\n\n"
    "Once you have enough information, give your final answer as exactly "
    "ONE short sentence (no more than ~20 words) stating precisely what the "
    "target function does - its core purpose only, not a step-by-step "
    "walkthrough. Do not restate the code line by line, and do not use "
    "markdown code fences or bullet points. This one sentence will be "
    "written verbatim into an IDA function comment, so keep it self-"
    "contained and free of REQUEST_CODE lines. If asked for more detail in "
    "a follow-up, you may then answer at greater length.\n\n"
    "In that same final answer only (never in a REQUEST_CODE-only reply), "
    "end with one extra line of the exact form\n"
    "SUGGESTED_NAME: <name>\n"
    "proposing a better name for the target function, based on what it "
    "actually does. The name must be a valid C identifier: letters, digits "
    "and underscores only, not starting with a digit, no spaces. Prefer "
    "short, conventional reverse-engineering style names (e.g. "
    "parse_http_header, aes_decrypt_block). Omit this line only if the "
    "function is already named descriptively and a rename would not help.\n\n"
    "If, and only if, the target function's own code was given to you as "
    "Hex-Rays pseudocode (not plain disassembly), also try to infer better "
    "types and names for its return value, arguments, and local variables:\n"
    "1. If you can determine a more accurate prototype than the one shown "
    "(return type, argument types, and/or argument names), add one line of "
    "the exact form\n"
    "SUGGESTED_SIGNATURE: <full C declaration>\n"
    "e.g. SUGGESTED_SIGNATURE: int __cdecl parse_header(char *buf, int len)\n"
    "Use this only for the return type and the function's own arguments, "
    "never for local variables.\n"
    "2. For local variables (not arguments) whose default compiler-generated "
    "name (e.g. v1, v2, a1) could be replaced with something more "
    "descriptive, add one line per variable of the exact form\n"
    "SUGGESTED_VAR: <current_name> -> <new_name>\n"
    "Only propose types or variable names you are reasonably confident "
    "about from the code itself; skip anything uncertain. Omit both kinds "
    "of lines entirely when you were given plain disassembly instead of "
    "pseudocode, or when you have nothing confident to suggest."
)

DEFAULT_CONFIG = {
    "base_url": "http://127.0.0.1:8080",
    "model": "",
    "api_key": "",
    "temperature": 0.2,
    "max_tokens": 16384,
    "request_timeout": 300,
    "max_context_chars": 12000,
    "include_callees": True,
    "max_callees": 20,
    "follow_calls_depth": 0,
    "max_total_context_chars": 40000,
    "max_auto_fetch": 5,
    "system_prompt": DEFAULT_SYSTEM_PROMPT,
    "explain_hotkey": "Ctrl-Alt-E",
}

ContextBundle = namedtuple("ContextBundle", ["kind", "text"])

# Safety valve for eager recursive call-following: never eagerly decompile
# more than this many functions for one initial request, regardless of the
# configured depth/char budget (deep or wide call graphs could otherwise
# make the initial request very slow).
_MAX_EAGER_FUNCTIONS = 40

_REQUEST_CODE_RE = re.compile(r"(?im)^\s*REQUEST_CODE:\s*(.+?)\s*$")
_SUGGESTED_NAME_RE = re.compile(r"(?im)^\s*SUGGESTED_NAME:\s*(.+?)\s*$")
_SUGGESTED_SIGNATURE_RE = re.compile(r"(?im)^\s*SUGGESTED_SIGNATURE:\s*(.+?)\s*$")
_SUGGESTED_VAR_RE = re.compile(r"(?im)^\s*SUGGESTED_VAR:\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*$")
_VALID_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_AUTO_NAME_RE = re.compile(r"^(sub|loc|nullsub|j_sub|j_nullsub)_[0-9A-Fa-f]+$")


def sanitize_suggested_name(name):
    if not name:
        return None
    name = name.strip().strip("`'\"").rstrip(".")
    if _VALID_NAME_RE.match(name):
        return name
    return None


def is_auto_generated_name(name):
    return bool(name) and bool(_AUTO_NAME_RE.match(name))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def strip_markdown_fences(text):
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z0-9_+\-]*\s*\n", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def get_procname():
    if ida_ida is not None:
        try:
            return ida_ida.inf_get_procname()
        except Exception:
            pass
    try:
        return idc.get_inf_attr(idc.INF_PROCNAME)
    except Exception:
        return "unknown"


def gather_function_context(func):
    """Prefer Hex-Rays pseudocode; fall back to a plain disassembly listing."""
    cfunc = None
    if ida_hexrays is not None:
        try:
            if ida_hexrays.init_hexrays_plugin():
                cfunc = ida_hexrays.decompile(func)
        except Exception:
            cfunc = None
    if cfunc is not None:
        try:
            lines = [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]
            return ContextBundle(kind="pseudocode", text="\n".join(lines))
        except Exception:
            pass

    lines = []
    for ea in idautils.FuncItems(func.start_ea):
        try:
            line = idc.generate_disasm_line(ea, idc.GENDSM_REMOVE_TAGS)
        except Exception:
            line = idc.GetDisasm(ea)
        if line:
            line = ida_lines.tag_remove(line)
        lines.append("%#010x  %s" % (ea, line or ""))
    return ContextBundle(kind="disassembly", text="\n".join(lines))


def gather_callee_funcs(func, max_callees):
    """Direct callees of func, as func_t objects, in first-seen order."""
    if max_callees <= 0:
        return []
    result = []
    seen = set()
    for ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.CodeRefsFrom(ea, 0):
            callee = ida_funcs.get_func(ref)
            if callee and callee.start_ea == ref and ref != func.start_ea and ref not in seen:
                seen.add(ref)
                result.append(callee)
        if len(result) >= max_callees:
            break
    return result[:max_callees]


def format_function_block(label, func_ea, ctx, config):
    name = ida_funcs.get_func_name(func_ea) or ("sub_%X" % func_ea)
    body = ctx.text
    if len(body) > config.max_context_chars:
        body = body[: config.max_context_chars] + "\n...[truncated]..."
    kind_label = "Pseudocode (Hex-Rays)" if ctx.kind == "pseudocode" else "Disassembly"
    return "--- %s: %s @ %#010x (%s) ---\n%s" % (label, name, func_ea, kind_label, body)


def gather_recursive_context(root_func, config):
    """Breadth-first walk of the call graph starting at root_func, up to
    config.follow_calls_depth levels. Returns a list of
    (depth, func_ea, ContextBundle) tuples, root first (depth 0). Bounded by
    config.max_total_context_chars and _MAX_EAGER_FUNCTIONS to keep the
    initial request fast even for large/recursive call graphs.
    """
    visited = {root_func.start_ea}
    root_ctx = gather_function_context(root_func)
    blocks = [(0, root_func.start_ea, root_ctx)]
    total_chars = len(root_ctx.text)
    frontier = [root_func]
    depth = 0
    while (
        depth < config.follow_calls_depth
        and frontier
        and total_chars < config.max_total_context_chars
        and len(visited) < _MAX_EAGER_FUNCTIONS
    ):
        next_frontier = []
        for func in frontier:
            for callee in gather_callee_funcs(func, config.max_callees):
                if callee.start_ea in visited:
                    continue
                if total_chars >= config.max_total_context_chars or len(visited) >= _MAX_EAGER_FUNCTIONS:
                    break
                visited.add(callee.start_ea)
                try:
                    ctx = gather_function_context(callee)
                except Exception:
                    continue
                blocks.append((depth + 1, callee.start_ea, ctx))
                total_chars += len(ctx.text)
                next_frontier.append(callee)
        frontier = next_frontier
        depth += 1
    return blocks


def resolve_function_query(query):
    """Resolve a model-supplied identifier (name or address) to a func_t."""
    query = (query or "").strip().strip("`'\"")
    if not query:
        return None
    ea = idc.get_name_ea_simple(query)
    if ea == idaapi.BADADDR:
        for base in (0, 16):
            try:
                ea = int(query, base)
                break
            except ValueError:
                ea = idaapi.BADADDR
    if ea == idaapi.BADADDR:
        return None
    return ida_funcs.get_func(ea)


def build_user_message(config, func, blocks, callee_names):
    name = ida_funcs.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
    header = (
        "Function: %s\n"
        "Address: %#010x\n"
        "Architecture: %s\n" % (name, func.start_ea, get_procname())
    )
    if callee_names:
        header += "Calls: %s\n" % ", ".join(callee_names)
    if config.follow_calls_depth > 0:
        header += (
            "Code for up to %d level(s) of called functions is included "
            "below where available.\n" % config.follow_calls_depth
        )
    parts = [header]
    for depth, ea, ctx in blocks:
        label = "Target function" if depth == 0 else ("Called function (depth %d)" % depth)
        parts.append(format_function_block(label, ea, ctx, config))
    return "\n".join(parts)


def _resolve_func(ctx):
    ea = getattr(ctx, "cur_ea", None)
    if ea is None or ea == idaapi.BADADDR:
        ea = ida_kernwin.get_screen_ea()
    return ida_funcs.get_func(ea)


def _apply_suggestions_and_refresh(func_ea, comment, new_name=None, signature=None, var_renames=None):
    try:
        idc.set_func_cmt(func_ea, comment, 0)
    except Exception as exc:
        ida_kernwin.msg("[%s] Failed to set comment: %s\n" % (PLUGIN_NAME, exc))

    if signature:
        try:
            decl = signature.strip()
            if not decl.endswith(";"):
                decl += ";"
            if not idc.SetType(func_ea, decl):
                ida_kernwin.msg("[%s] Failed to apply signature: %s\n" % (PLUGIN_NAME, signature))
        except Exception as exc:
            ida_kernwin.msg("[%s] Failed to apply signature '%s': %s\n" % (PLUGIN_NAME, signature, exc))

    if new_name:
        try:
            ok = ida_name.set_name(func_ea, new_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
            if not ok:
                ida_kernwin.msg("[%s] Failed to rename function to '%s'.\n" % (PLUGIN_NAME, new_name))
        except Exception as exc:
            ida_kernwin.msg("[%s] Failed to rename function: %s\n" % (PLUGIN_NAME, exc))

    if var_renames and ida_hexrays is not None:
        try:
            hexrays_ready = ida_hexrays.init_hexrays_plugin()
        except Exception:
            hexrays_ready = False
        if hexrays_ready:
            for old_name, new_name_var in var_renames:
                try:
                    if not ida_hexrays.rename_lvar(func_ea, old_name, new_name_var):
                        ida_kernwin.msg(
                            "[%s] Failed to rename variable '%s' -> '%s'.\n" % (PLUGIN_NAME, old_name, new_name_var)
                        )
                except Exception as exc:
                    ida_kernwin.msg("[%s] Failed to rename variable '%s': %s\n" % (PLUGIN_NAME, old_name, exc))

    try:
        if ida_hexrays is not None and ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(func_ea)
    except Exception:
        pass
    try:
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM | ida_kernwin.IWID_PSEUDOCODE)
    except Exception:
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
    return 1


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class PluginConfig(object):
    _FIELDS = list(DEFAULT_CONFIG.keys())

    def __init__(self, **kwargs):
        data = dict(DEFAULT_CONFIG)
        data.update({k: v for k, v in kwargs.items() if k in data})
        for key, value in data.items():
            setattr(self, key, value)
        self._validate()

    @staticmethod
    def _config_path():
        return os.path.join(idaapi.get_user_idadir(), CONFIG_FILENAME)

    @classmethod
    def load(cls):
        data = {}
        try:
            with open(cls._config_path(), "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except FileNotFoundError:
            pass
        except Exception as exc:
            ida_kernwin.msg("[%s] Failed to read config (%s); using defaults.\n" % (PLUGIN_NAME, exc))
        return cls(**data)

    def save(self):
        self._validate()
        path = self._config_path()
        tmp_path = path + ".tmp"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, indent=2)
            os.replace(tmp_path, path)
        except Exception as exc:
            ida_kernwin.msg("[%s] Failed to save config: %s\n" % (PLUGIN_NAME, exc))

    def to_dict(self):
        return {key: getattr(self, key) for key in self._FIELDS}

    def clone(self):
        return PluginConfig(**self.to_dict())

    def _validate(self):
        self.base_url = (self.base_url or DEFAULT_CONFIG["base_url"]).strip().rstrip("/")
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            self.base_url = DEFAULT_CONFIG["base_url"]
        try:
            self.temperature = max(0.0, min(2.0, float(self.temperature)))
        except (TypeError, ValueError):
            self.temperature = DEFAULT_CONFIG["temperature"]
        try:
            self.max_tokens = max(1, int(self.max_tokens))
        except (TypeError, ValueError):
            self.max_tokens = DEFAULT_CONFIG["max_tokens"]
        try:
            self.request_timeout = max(1, int(self.request_timeout))
        except (TypeError, ValueError):
            self.request_timeout = DEFAULT_CONFIG["request_timeout"]
        try:
            self.max_context_chars = max(500, int(self.max_context_chars))
        except (TypeError, ValueError):
            self.max_context_chars = DEFAULT_CONFIG["max_context_chars"]
        try:
            self.max_callees = max(0, int(self.max_callees))
        except (TypeError, ValueError):
            self.max_callees = DEFAULT_CONFIG["max_callees"]
        try:
            self.follow_calls_depth = max(0, min(5, int(self.follow_calls_depth)))
        except (TypeError, ValueError):
            self.follow_calls_depth = DEFAULT_CONFIG["follow_calls_depth"]
        try:
            self.max_total_context_chars = max(self.max_context_chars, int(self.max_total_context_chars))
        except (TypeError, ValueError):
            self.max_total_context_chars = DEFAULT_CONFIG["max_total_context_chars"]
        try:
            self.max_auto_fetch = max(0, int(self.max_auto_fetch))
        except (TypeError, ValueError):
            self.max_auto_fetch = DEFAULT_CONFIG["max_auto_fetch"]
        self.model = (self.model or "").strip()
        self.api_key = (self.api_key or "").strip()
        self.system_prompt = self.system_prompt or DEFAULT_SYSTEM_PROMPT
        self.explain_hotkey = (self.explain_hotkey or "").strip()
        self.include_callees = bool(self.include_callees)


# ---------------------------------------------------------------------------
# Networking (background thread, SSE streaming over urllib)
# ---------------------------------------------------------------------------

class LlamaStreamWorker(threading.Thread):
    """Runs one chat-completion request against llama-server, streaming the
    answer via SSE. All callbacks are marshalled onto IDA's main thread with
    execute_sync; this thread never touches Qt widgets or the IDA database
    directly.
    """

    def __init__(self, config, messages, on_delta, on_reasoning_delta, on_done, on_error):
        super().__init__(daemon=True)
        self._config = config
        self._messages = messages
        self._on_delta = on_delta
        self._on_reasoning_delta = on_reasoning_delta
        self._on_done = on_done
        self._on_error = on_error
        self._cancel_event = threading.Event()
        self._response = None

    def cancel(self):
        self._cancel_event.set()
        resp = self._response
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    def run(self):
        try:
            self._stream()
        except Exception as exc:
            if not self._cancel_event.is_set():
                ida_kernwin.execute_sync(
                    functools.partial(self._on_error, str(exc)), ida_kernwin.MFF_FAST
                )

    def _stream(self):
        url = self._config.base_url + "/v1/chat/completions"
        payload = {
            "messages": self._messages,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
            "stream": True,
        }
        if self._config.model:
            payload["model"] = self._config.model
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self._config.api_key:
            headers["Authorization"] = "Bearer " + self._config.api_key

        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            self._response = urllib.request.urlopen(req, timeout=self._config.request_timeout)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:2000]
            except Exception:
                pass
            raise RuntimeError("HTTP %s: %s" % (exc.code, body)) from None
        except urllib.error.URLError as exc:
            raise RuntimeError("Cannot connect to %s (%s)" % (url, exc.reason)) from None

        parts = []
        reasoning_parts = []
        finish_reason = [None]
        with self._response as resp:
            content_type = resp.headers.get("Content-Type", "")
            if not content_type.startswith("text/event-stream"):
                self._handle_non_stream_body(resp.read(), parts, reasoning_parts, finish_reason)
            else:
                for raw_line in resp:
                    if self._cancel_event.is_set():
                        return
                    line = raw_line.decode("utf-8", "replace").strip("\r\n")
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[len("data:"):].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        obj = json.loads(data_str)
                    except ValueError:
                        continue
                    choices = obj.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    if choices[0].get("finish_reason"):
                        finish_reason[0] = choices[0].get("finish_reason")
                    # Reasoning/"thinking" models (e.g. Qwen3) stream their
                    # chain-of-thought separately from the real answer.
                    reasoning_piece = delta.get("reasoning_content")
                    if reasoning_piece:
                        reasoning_parts.append(reasoning_piece)
                        ida_kernwin.execute_sync(
                            functools.partial(self._on_reasoning_delta, reasoning_piece), ida_kernwin.MFF_FAST
                        )
                    piece = delta.get("content")
                    if piece:
                        parts.append(piece)
                        ida_kernwin.execute_sync(
                            functools.partial(self._on_delta, piece), ida_kernwin.MFF_FAST
                        )

        if not self._cancel_event.is_set():
            ida_kernwin.execute_sync(
                functools.partial(
                    self._on_done, "".join(parts), "".join(reasoning_parts), finish_reason[0]
                ),
                ida_kernwin.MFF_FAST,
            )

    def _handle_non_stream_body(self, body, parts, reasoning_parts, finish_reason):
        try:
            obj = json.loads(body.decode("utf-8", "replace"))
        except Exception as exc:
            raise RuntimeError("Unexpected response from server: %s" % exc) from None
        choices = obj.get("choices") or []
        if not choices:
            err = obj.get("error")
            raise RuntimeError(str(err) if err else "Empty response from server.")
        finish_reason[0] = choices[0].get("finish_reason")
        message = choices[0].get("message") or {}
        reasoning = message.get("reasoning_content", "")
        if reasoning:
            reasoning_parts.append(reasoning)
            ida_kernwin.execute_sync(
                functools.partial(self._on_reasoning_delta, reasoning), ida_kernwin.MFF_FAST
            )
        content = message.get("content", "")
        if content:
            parts.append(content)
            ida_kernwin.execute_sync(
                functools.partial(self._on_delta, content), ida_kernwin.MFF_FAST
            )


# ---------------------------------------------------------------------------
# UI: result dialog
# ---------------------------------------------------------------------------

class ExplainResultDialog(QtWidgets.QDialog):
    def __init__(self, config, func, parent=None):
        super().__init__(parent)
        self.config = config
        self.func_ea = func.start_ea
        self.func_name = ida_funcs.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
        self.worker = None
        self.messages = None
        self._buffer = []
        self._reasoning_buffer = []
        self._reasoning_shown = False
        self._last_answer_text = ""
        self._closed = False
        self._fetched_eas = set()
        self._auto_fetch_rounds = 0
        self._forced_final = False
        self._suggested_name = None
        self._suggested_signature = None
        self._suggested_vars = []
        self._root_is_pseudocode = False

        self.setWindowTitle("%s - %s @ %#x" % (PLUGIN_NAME, self.func_name, func.start_ea))
        self.resize(560, 520)

        layout = QtWidgets.QVBoxLayout(self)

        self.status_label = QtWidgets.QLabel("Contacting model...")
        layout.addWidget(self.status_label)

        self.stream_edit = QtWidgets.QPlainTextEdit()
        self.stream_edit.setReadOnly(True)
        self.stream_edit.setFont(QtGui.QFont("Consolas", 9))
        layout.addWidget(self.stream_edit, 1)

        followup_layout = QtWidgets.QHBoxLayout()
        self.followup_input = QtWidgets.QLineEdit()
        self.followup_input.setPlaceholderText(
            "Ask a follow-up question or request more detail, then click Reason More..."
        )
        self.followup_input.returnPressed.connect(self.on_reason_more)
        followup_layout.addWidget(self.followup_input, 1)
        self.reason_button = QtWidgets.QPushButton("Reason More")
        self.reason_button.clicked.connect(self.on_reason_more)
        self.reason_button.setEnabled(False)
        followup_layout.addWidget(self.reason_button)
        layout.addLayout(followup_layout)

        rename_layout = QtWidgets.QHBoxLayout()
        self.rename_check = QtWidgets.QCheckBox("Rename function to:")
        self.rename_check.setEnabled(False)
        rename_layout.addWidget(self.rename_check)
        self.rename_edit = QtWidgets.QLineEdit()
        self.rename_edit.setEnabled(False)
        rename_layout.addWidget(self.rename_edit, 1)
        layout.addLayout(rename_layout)

        signature_layout = QtWidgets.QHBoxLayout()
        self.signature_check = QtWidgets.QCheckBox("Apply suggested signature:")
        self.signature_check.setEnabled(False)
        signature_layout.addWidget(self.signature_check)
        self.signature_edit = QtWidgets.QLineEdit()
        self.signature_edit.setEnabled(False)
        signature_layout.addWidget(self.signature_edit, 1)
        layout.addLayout(signature_layout)

        varrename_layout = QtWidgets.QHBoxLayout()
        self.varrename_check = QtWidgets.QCheckBox("Apply suggested variable renames:")
        self.varrename_check.setEnabled(False)
        varrename_layout.addWidget(self.varrename_check)
        self.varrename_label = QtWidgets.QLineEdit()
        self.varrename_label.setReadOnly(True)
        self.varrename_label.setEnabled(False)
        varrename_layout.addWidget(self.varrename_label, 1)
        layout.addLayout(varrename_layout)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch(1)
        self.accept_button = QtWidgets.QPushButton("Accept && Add Comment")
        self.accept_button.clicked.connect(self.on_accept)
        self.accept_button.setEnabled(False)
        button_layout.addWidget(self.accept_button)
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.close)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self._start_initial_request(func)

    # -- request lifecycle --------------------------------------------------

    def _start_initial_request(self, func):
        try:
            blocks = gather_recursive_context(func, self.config)
            callee_funcs = gather_callee_funcs(func, self.config.max_callees) if self.config.include_callees else []
            callee_names = [
                ida_funcs.get_func_name(f.start_ea) or ("sub_%X" % f.start_ea) for f in callee_funcs
            ]
            user_msg = build_user_message(self.config, func, blocks, callee_names)
        except Exception as exc:
            self.status_label.setText("Failed to gather function context: %s" % exc)
            return
        self._fetched_eas = {ea for _, ea, _ in blocks}
        self._root_is_pseudocode = bool(blocks) and blocks[0][2].kind == "pseudocode"
        self.messages = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": user_msg},
        ]
        self.start_request()

    def start_request(self):
        self._buffer = []
        self._reasoning_buffer = []
        self._reasoning_shown = False
        self.status_label.setText("Querying model...")
        self.reason_button.setEnabled(False)
        self.followup_input.setEnabled(False)
        self.worker = LlamaStreamWorker(
            self.config, list(self.messages), self._on_delta, self._on_reasoning_delta,
            self._on_done, self._on_error
        )
        self.worker.start()

    # -- worker callbacks (run on IDA's main thread via execute_sync) -------

    def _insert_styled(self, text, italic=False, color=None):
        try:
            cursor = self.stream_edit.textCursor()
            cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
            fmt = QtGui.QTextCharFormat()
            fmt.setFontItalic(italic)
            if color is not None:
                fmt.setForeground(color)
            cursor.insertText(text, fmt)
            self.stream_edit.setTextCursor(cursor)
            self.stream_edit.ensureCursorVisible()
        except RuntimeError:
            pass

    def _on_reasoning_delta(self, piece):
        if self._closed:
            return 0
        self._reasoning_buffer.append(piece)
        if not self._reasoning_shown:
            self._reasoning_shown = True
            self._insert_styled("[thinking] ", italic=True, color=QtGui.QColor("gray"))
        self._insert_styled(piece, italic=True, color=QtGui.QColor("gray"))
        return 0

    def _on_delta(self, piece):
        if self._closed:
            return 0
        if self._reasoning_shown:
            self._reasoning_shown = False
            self._insert_styled("\n\n")
        self._buffer.append(piece)
        self._insert_styled(piece)
        return 0

    def _on_done(self, full_text, reasoning_text="", finish_reason=None):
        if self._closed:
            return 0
        text = full_text if full_text else "".join(self._buffer)
        reasoning = reasoning_text if reasoning_text else "".join(self._reasoning_buffer)

        if not text.strip():
            # Nothing usable came back - don't pollute the conversation history
            # with an empty assistant turn, just explain what happened.
            if reasoning.strip():
                self.status_label.setText(
                    "Model spent its whole token budget on reasoning and gave no "
                    "answer (finish_reason=%s). Increase 'Max tokens' in Settings, "
                    "or click Reason More to ask it to wrap up." % (finish_reason or "unknown")
                )
            else:
                self.status_label.setText(
                    "Model returned an empty response (finish_reason=%s)." % (finish_reason or "unknown")
                )
            self.reason_button.setEnabled(True)
            self.followup_input.setEnabled(True)
            self.accept_button.setEnabled(False)
            self.worker = None
            return 0

        if self.messages is not None:
            self.messages.append({"role": "assistant", "content": text})

        requests = _REQUEST_CODE_RE.findall(text)
        if requests and not self._forced_final:
            if self._auto_fetch_rounds < self.config.max_auto_fetch:
                self._auto_fetch_rounds += 1
                self._handle_code_requests(requests)
                return 0
            self._forced_final = True
            self.messages.append({
                "role": "user",
                "content": (
                    "You have reached the maximum number of code requests (%d). "
                    "Please give your best explanation now based on the "
                    "information already gathered, without requesting further "
                    "code." % self.config.max_auto_fetch
                ),
            })
            self.status_label.setText("Auto-fetch limit reached; asking for a final answer...")
            self.start_request()
            return 0

        name_matches = _SUGGESTED_NAME_RE.findall(text)
        if name_matches:
            text = _SUGGESTED_NAME_RE.sub("", text).strip()
            candidate = sanitize_suggested_name(name_matches[-1])
            if candidate:
                self._suggested_name = candidate
                self.rename_edit.setText(candidate)
                self.rename_check.setEnabled(True)
                self.rename_edit.setEnabled(True)
                self.rename_check.setChecked(is_auto_generated_name(self.func_name))

        sig_matches = _SUGGESTED_SIGNATURE_RE.findall(text)
        if sig_matches:
            text = _SUGGESTED_SIGNATURE_RE.sub("", text).strip()
            candidate = sig_matches[-1].strip()
            if candidate and self._root_is_pseudocode:
                self._suggested_signature = candidate
                self.signature_edit.setText(candidate)
                self.signature_check.setEnabled(True)
                self.signature_edit.setEnabled(True)
                self.signature_check.setChecked(True)

        var_matches = _SUGGESTED_VAR_RE.findall(text)
        if var_matches:
            text = _SUGGESTED_VAR_RE.sub("", text).strip()
            if self._root_is_pseudocode:
                pairs = []
                seen_old = set()
                for old_name, new_name_var in var_matches:
                    if old_name != new_name_var and old_name not in seen_old:
                        seen_old.add(old_name)
                        pairs.append((old_name, new_name_var))
                if pairs:
                    self._suggested_vars = pairs
                    self.varrename_label.setText(", ".join("%s -> %s" % p for p in pairs))
                    self.varrename_check.setEnabled(True)
                    self.varrename_label.setEnabled(True)
                    self.varrename_check.setChecked(True)

        self._last_answer_text = text
        self.status_label.setText("Done.")
        self.reason_button.setEnabled(True)
        self.followup_input.setEnabled(True)
        self.accept_button.setEnabled(bool(text.strip()))
        self.worker = None
        return 0

    def _handle_code_requests(self, requests):
        self.status_label.setText("Model requested more code, fetching...")
        reply_parts = []
        queried = []
        seen_this_round = set()
        for query in requests:
            query = query.strip()
            if not query or query in seen_this_round:
                continue
            seen_this_round.add(query)
            queried.append(query)
            func = resolve_function_query(query)
            if func is None:
                reply_parts.append("No function found matching '%s'." % query)
                continue
            if func.start_ea in self._fetched_eas:
                name = ida_funcs.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
                reply_parts.append("You already have the code for %s (see above)." % name)
                continue
            try:
                ctx = gather_function_context(func)
            except Exception as exc:
                reply_parts.append("Failed to retrieve code for '%s': %s" % (query, exc))
                continue
            self._fetched_eas.add(func.start_ea)
            reply_parts.append(format_function_block("Requested function", func.start_ea, ctx, self.config))

        reply_text = "\n\n".join(reply_parts) if reply_parts else "No additional code available."
        self.messages.append({"role": "user", "content": reply_text})
        try:
            self.stream_edit.appendPlainText(
                "\n\n--- Fetching requested code (%s) ---\n" % ", ".join(queried)
            )
        except RuntimeError:
            pass
        self.start_request()

    def _on_error(self, message):
        if self._closed:
            return 0
        self.status_label.setText("Error: %s" % message)
        self.reason_button.setEnabled(True)
        self.followup_input.setEnabled(True)
        partial = "".join(self._buffer).strip()
        self.accept_button.setEnabled(bool(partial or self._last_answer_text.strip()))
        self.worker = None
        return 0

    # -- button handlers ------------------------------------------------

    def on_reason_more(self):
        if self.worker is not None or self.messages is None:
            return
        followup = self.followup_input.text().strip()
        if not followup:
            followup = "Please explain your reasoning in more detail."
        self.messages.append({"role": "user", "content": followup})
        self.followup_input.clear()
        self._forced_final = False
        try:
            self.stream_edit.appendPlainText("\n\n--- Follow-up: %s ---\n" % followup)
        except RuntimeError:
            pass
        self.start_request()

    def on_accept(self):
        text = (self._last_answer_text or "".join(self._buffer)).strip()
        if not text:
            ida_kernwin.warning("Nothing to accept yet.")
            return
        comment = strip_markdown_fences(text)
        comment = _REQUEST_CODE_RE.sub("", comment)
        comment = _SUGGESTED_NAME_RE.sub("", comment)
        comment = _SUGGESTED_SIGNATURE_RE.sub("", comment)
        comment = _SUGGESTED_VAR_RE.sub("", comment).strip()

        new_name = None
        if self.rename_check.isChecked():
            new_name = sanitize_suggested_name(self.rename_edit.text())
            if not new_name:
                ida_kernwin.warning(
                    "'%s' is not a valid function name; skipping rename." % self.rename_edit.text()
                )

        signature = None
        if self.signature_check.isChecked() and self.signature_edit.text().strip():
            signature = self.signature_edit.text().strip()

        var_renames = list(self._suggested_vars) if (self.varrename_check.isChecked() and self._suggested_vars) else None

        ida_kernwin.execute_sync(
            functools.partial(
                _apply_suggestions_and_refresh, self.func_ea, comment, new_name, signature, var_renames
            ),
            ida_kernwin.MFF_WRITE,
        )
        self.close()

    def closeEvent(self, event):
        self._closed = True
        if self.worker is not None:
            self.worker.cancel()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# UI: settings dialog
# ---------------------------------------------------------------------------

class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.setWindowTitle("%s Settings" % PLUGIN_NAME)
        self.resize(480, 520)
        self.result_config = None
        self._base_config = config

        form = QtWidgets.QFormLayout()

        self.base_url_edit = QtWidgets.QLineEdit()
        form.addRow("Server base URL:", self.base_url_edit)

        self.model_edit = QtWidgets.QLineEdit()
        self.model_edit.setPlaceholderText("(optional - leave blank to use server default)")
        form.addRow("Model name:", self.model_edit)

        self.api_key_edit = QtWidgets.QLineEdit()
        self.api_key_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("(optional bearer token)")
        form.addRow("API key:", self.api_key_edit)

        self.temperature_spin = QtWidgets.QDoubleSpinBox()
        self.temperature_spin.setRange(0.0, 2.0)
        self.temperature_spin.setSingleStep(0.1)
        form.addRow("Temperature:", self.temperature_spin)

        self.max_tokens_spin = QtWidgets.QSpinBox()
        self.max_tokens_spin.setRange(1, 262144)
        self.max_tokens_spin.setToolTip(
            "Reasoning/thinking models can spend thousands of tokens on "
            "chain-of-thought before producing a real answer - keep this "
            "generous, well below the server's context size."
        )
        form.addRow("Max tokens:", self.max_tokens_spin)

        self.timeout_spin = QtWidgets.QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setToolTip(
            "This is a per-chunk socket timeout, not a total-generation cap - "
            "it mainly needs headroom for slow prompt processing or a stalled "
            "gap between streamed tokens on local/CPU inference."
        )
        form.addRow("Request timeout (s):", self.timeout_spin)

        self.max_context_spin = QtWidgets.QSpinBox()
        self.max_context_spin.setRange(500, 200000)
        self.max_context_spin.setSingleStep(500)
        form.addRow("Max context chars:", self.max_context_spin)

        self.include_callees_check = QtWidgets.QCheckBox("Include called-function names in prompt")
        form.addRow(self.include_callees_check)

        self.max_callees_spin = QtWidgets.QSpinBox()
        self.max_callees_spin.setRange(0, 200)
        form.addRow("Max callees listed:", self.max_callees_spin)

        self.follow_calls_spin = QtWidgets.QSpinBox()
        self.follow_calls_spin.setRange(0, 5)
        self.follow_calls_spin.setToolTip(
            "0 = only the target function. N>0 eagerly includes the code of "
            "called functions up to N levels deep in the initial prompt."
        )
        form.addRow("Follow calls depth:", self.follow_calls_spin)

        self.max_total_context_spin = QtWidgets.QSpinBox()
        self.max_total_context_spin.setRange(1000, 1000000)
        self.max_total_context_spin.setSingleStep(1000)
        self.max_total_context_spin.setToolTip(
            "Overall char budget across the target function plus all "
            "eagerly-followed called functions combined."
        )
        form.addRow("Max total context chars:", self.max_total_context_spin)

        self.max_auto_fetch_spin = QtWidgets.QSpinBox()
        self.max_auto_fetch_spin.setRange(0, 50)
        self.max_auto_fetch_spin.setToolTip(
            "Max number of automatic REQUEST_CODE round-trips the model may "
            "make per conversation before being asked for a final answer."
        )
        form.addRow("Max on-demand code requests:", self.max_auto_fetch_spin)

        self.hotkey_edit = QtWidgets.QLineEdit()
        self.hotkey_edit.setPlaceholderText("e.g. Ctrl-Alt-E (leave blank for none)")
        form.addRow("Explain hotkey:", self.hotkey_edit)

        self.system_prompt_edit = QtWidgets.QPlainTextEdit()
        self.system_prompt_edit.setMinimumHeight(140)
        form.addRow("System prompt:", self.system_prompt_edit)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            | QtWidgets.QDialogButtonBox.StandardButton.RestoreDefaults
        )
        buttons.accepted.connect(self._on_ok)
        buttons.rejected.connect(self.reject)
        buttons.button(QtWidgets.QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(
            self._on_restore_defaults
        )

        outer = QtWidgets.QVBoxLayout(self)
        outer.addLayout(form)
        outer.addWidget(buttons)

        self._populate(config)

    def _populate(self, config):
        self.base_url_edit.setText(config.base_url)
        self.model_edit.setText(config.model)
        self.api_key_edit.setText(config.api_key)
        self.temperature_spin.setValue(config.temperature)
        self.max_tokens_spin.setValue(config.max_tokens)
        self.timeout_spin.setValue(config.request_timeout)
        self.max_context_spin.setValue(config.max_context_chars)
        self.include_callees_check.setChecked(config.include_callees)
        self.max_callees_spin.setValue(config.max_callees)
        self.follow_calls_spin.setValue(config.follow_calls_depth)
        self.max_total_context_spin.setValue(config.max_total_context_chars)
        self.max_auto_fetch_spin.setValue(config.max_auto_fetch)
        self.hotkey_edit.setText(config.explain_hotkey)
        self.system_prompt_edit.setPlainText(config.system_prompt)

    def _on_restore_defaults(self):
        answer = QtWidgets.QMessageBox.question(
            self,
            "Restore Defaults",
            "Reset all settings on this screen to their default values?\n"
            "Nothing is saved until you click OK.",
        )
        if answer == QtWidgets.QMessageBox.StandardButton.Yes:
            self._populate(PluginConfig())

    def _on_ok(self):
        cfg = self._base_config.clone()
        cfg.base_url = self.base_url_edit.text()
        cfg.model = self.model_edit.text()
        cfg.api_key = self.api_key_edit.text()
        cfg.temperature = self.temperature_spin.value()
        cfg.max_tokens = self.max_tokens_spin.value()
        cfg.request_timeout = self.timeout_spin.value()
        cfg.max_context_chars = self.max_context_spin.value()
        cfg.include_callees = self.include_callees_check.isChecked()
        cfg.max_callees = self.max_callees_spin.value()
        cfg.follow_calls_depth = self.follow_calls_spin.value()
        cfg.max_total_context_chars = self.max_total_context_spin.value()
        cfg.max_auto_fetch = self.max_auto_fetch_spin.value()
        cfg.explain_hotkey = self.hotkey_edit.text().strip()
        cfg.system_prompt = self.system_prompt_edit.toPlainText()
        cfg._validate()
        self.result_config = cfg
        self.accept()


# ---------------------------------------------------------------------------
# IDA action / popup / plugin glue
# ---------------------------------------------------------------------------

class ExplainActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        func = _resolve_func(ctx)
        if not func:
            ida_kernwin.warning("Place the cursor inside a function first.")
            return 0
        plugin = LLMExplainerPlugin.instance
        if plugin is None:
            return 0
        plugin.open_explain_dialog(func)
        return 1

    def update(self, ctx):
        widget = getattr(ctx, "widget", None)
        wtype = ida_kernwin.get_widget_type(widget) if widget else -1
        if wtype not in (ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if _resolve_func(ctx) else ida_kernwin.AST_DISABLE_FOR_WIDGET


class PopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype in (ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_ID_EXPLAIN, "LLM Explainer/")


class LLMExplainerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Ask a local llama.cpp model to explain the current function"
    help = (
        "Right-click a function in the disassembly or pseudocode view (or "
        "use the configured hotkey) to ask the configured llama.cpp server "
        "to explain it. Edit > Plugins > LLM Explainer opens settings."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    instance = None

    def init(self):
        LLMExplainerPlugin.instance = self
        self.config = PluginConfig.load()
        self._open_dialogs = []
        self._action_handler = ExplainActionHandler()

        action = ida_kernwin.action_desc_t(
            ACTION_ID_EXPLAIN,
            "Explain function with LLM...",
            self._action_handler,
            self.config.explain_hotkey or None,
            "Ask the local LLM (llama.cpp server) to explain this function",
            -1,
        )
        if not ida_kernwin.register_action(action):
            ida_kernwin.msg("[%s] Failed to register action.\n" % PLUGIN_NAME)

        self._popup_hooks = PopupHooks()
        self._popup_hooks.hook()

        ida_kernwin.msg("[%s] v%s loaded. Server: %s\n" % (PLUGIN_NAME, PLUGIN_VERSION, self.config.base_url))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        dlg = SettingsDialog(self.config)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted and dlg.result_config is not None:
            old_hotkey = self.config.explain_hotkey
            self.config = dlg.result_config
            self.config.save()
            if self.config.explain_hotkey != old_hotkey:
                try:
                    ida_kernwin.update_action_shortcut(ACTION_ID_EXPLAIN, self.config.explain_hotkey or None)
                except Exception:
                    try:
                        ida_kernwin.unregister_action(ACTION_ID_EXPLAIN)
                    except Exception:
                        pass
                    ida_kernwin.register_action(
                        ida_kernwin.action_desc_t(
                            ACTION_ID_EXPLAIN,
                            "Explain function with LLM...",
                            self._action_handler,
                            self.config.explain_hotkey or None,
                            "Ask the local LLM (llama.cpp server) to explain this function",
                            -1,
                        )
                    )

    def term(self):
        for dlg in list(self._open_dialogs):
            try:
                dlg.close()
            except Exception:
                pass
        self._open_dialogs = []
        try:
            self._popup_hooks.unhook()
        except Exception:
            pass
        try:
            ida_kernwin.unregister_action(ACTION_ID_EXPLAIN)
        except Exception:
            pass
        LLMExplainerPlugin.instance = None

    def open_explain_dialog(self, func):
        dlg = ExplainResultDialog(self.config, func)
        dlg.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
        self._open_dialogs.append(dlg)

        def _cleanup(_result=None, dialog=dlg):
            if dialog in self._open_dialogs:
                self._open_dialogs.remove(dialog)

        dlg.finished.connect(_cleanup)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
        return dlg


def PLUGIN_ENTRY():
    return LLMExplainerPlugin()
