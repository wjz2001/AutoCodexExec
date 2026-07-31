import argparse
import fnmatch
import hashlib
import io
import json
import math
import os
import queue
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import wave
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# 强制将标准输出和标准错误输出改为 UTF-8
for output_stream in (sys.stdout, sys.stderr):
    stream_encoding = getattr(output_stream, "encoding", None)
    reconfigure_stream = getattr(output_stream, "reconfigure", None)
    needs_utf8 = not isinstance(stream_encoding, str) or stream_encoding.lower() != "utf-8"
    if needs_utf8 and callable(reconfigure_stream):
        reconfigure_stream(encoding="utf-8")


class Colors:
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    DARK_GRAY = "\033[90m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"


_console_output_error: Optional[OSError] = None


def safe_print(*values: Any, **options: Any) -> Optional[OSError]:
    global _console_output_error
    if _console_output_error is not None:
        return _console_output_error
    try:
        print(*values, **options)
    except OSError as error:
        _console_output_error = error
    return _console_output_error


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_NAME = Path(__file__).name
SUPERVISOR_BLACK_BOX_RULE = (
    f"`{SCRIPT_NAME}` 是监督器黑盒，禁止定位、读取、检索、分析、修改，"
    "也不得把它纳入任务调查、项目扫描、上下文。"
)

# 首次规划时只需把完整需求填写在这里；已有规划续跑不会再次读取它。
PROJECT_REQUIREMENTS = r"""
""".strip()

GITIGNORE_FILE = SCRIPT_DIR / ".gitignore"
AUTOMATION_DIR = SCRIPT_DIR / ".codex-automation"
PLANNING_DIR = AUTOMATION_DIR / "planning"
WORKER_CONTROL_DIR = AUTOMATION_DIR / "worker-control"
LOG_DIR = AUTOMATION_DIR / "logs"
PERMISSION_ARCHIVE_DIR = AUTOMATION_DIR / "permissions"
RUN_STATE_FILE = AUTOMATION_DIR / "RUN_STATE.json"
PENDING_PERMISSION_FILE = WORKER_CONTROL_DIR / "PERMISSION_REQUEST.json"
APPROVAL_CLAIM_FILE = AUTOMATION_DIR / "APPROVAL_IN_PROGRESS.json"
AUTHORIZATION_FILE = AUTOMATION_DIR / "AUTHORIZATION.json"
PERMISSION_GRANTS_FILE = AUTOMATION_DIR / "PERMISSION_GRANTS.json"
SUPERVISOR_LOCK_FILE = AUTOMATION_DIR / "supervisor.lock"
SUPERVISOR_METADATA_FILE = AUTOMATION_DIR / "SUPERVISOR.json"
RULES_FILE = PLANNING_DIR / "RULES.md"
PLAN_FILE = PLANNING_DIR / "PLAN.md"
STATE_FILE = WORKER_CONTROL_DIR / "STATE.md"
TEMP_DIR = AUTOMATION_DIR / "tmp"
WORKSPACE_GUARD_BACKUP_ROOT = Path(tempfile.gettempdir()) / (
    "autocodex-workspace-guards-"
    + hashlib.sha256(str(SCRIPT_DIR).encode("utf-8")).hexdigest()[:16]
)
ALL_COMPLETED = "[ALL_COMPLETED]"
PLAN_FORMAT_VERSION = 3
PLAN_DATA_START = "<!-- AUTOCODEX_PLAN_START -->"
PLAN_DATA_END = "<!-- AUTOCODEX_PLAN_END -->"
ONE_PASS_TASK_STANDARD = """一次做对任务标准：
- 数量和压缩比例不是目标，也不得预设任务数量，只以执行模型能否在一次独立会话中无设计分歧地完成并验证为准。
- 同一任务仅在以下条件全部满足时成立：只有一个交付物和一个所有权边界；目标文件、关键符号、现有入口、必须复用的 API/组件/模式、禁止方案、实现顺序、相关行为矩阵、验证命令与预期结果都已明确；无需执行模型选择文件、API、数据模型、架构、验收方式。
- 任一 implementation 项可独立交付和验证、跨独立模块或 owner、需要不同验证环境或 human_action、workspace_root 只能扩大到项目根、allowed_paths 无法精确到文件、失败后无法从结构化摘要确定唯一续做点时，必须拆分。
- 只有拆开会产生不可编译、不可运行、无法独立验证的中间状态时才合并，共享验证命令本身不是合并理由。
- 调查、定位、盘点、分类、选择方案、架构设计必须由规划会话完成，结果直接写进任务，不得把这些决策留给 worker。
- preconditions 必须描述开始实现前可核对的具体代码状态。decision_constraints 必须分别包含以“必须：”“禁止：”“冲突时：”开头的条目，并引用具体文件、符号、API 或明确行为。“遵循现有架构”“按规则实现”等泛化文字无效。
"""
MAX_RAW_EVENT_TAIL_CHARS = 16 * 1024
PROCESS_OUTPUT_TAIL_LINES = 120
PERMISSION_ALERT_REPEAT_SECONDS = 300
QUIET_TIMEOUT_SECONDS = 1800
ABSOLUTE_TIMEOUT_SECONDS = 5400
PROCESS_OUTPUT_DRAIN_SECONDS = 10
PROCESS_TREE_DRAIN_SECONDS = 10
WINDOWS_CREATE_SUSPENDED = 0x00000004
MAX_TRANSIENT_FAILURES = 3
MAX_WINDOWS_SANDBOX_FAILURES = 2
MAX_NO_PROGRESS = 2
MAX_WORKSPACE_GUARD_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
WORKSPACE_GUARD_FREE_SPACE_RESERVE_BYTES = 512 * 1024 * 1024
TEMP_ENTRY_STALE_SECONDS = ABSOLUTE_TIMEOUT_SECONDS + 600
AUTHORIZATION_AREA = "project_rule_protected_changes"
AUTHORIZATION_AREA_LABEL = "受项目规则保护的修改"
AUTHORIZATION_RULE_PATTERNS = (
    re.compile(r"AUTOCODEX_MODIFICATION_AUTHORIZATION\s*[:=]\s*required", re.IGNORECASE),
    re.compile(
        r"未经(?:用户)?(?:明确)?(?:同意|批准|授权|许可|允许|确认)[^\n]{0,120}"
        r"(?:不得|禁止|不可|不能)[^\n]{0,120}(?:修改|变更|写入|删除)"
    ),
    re.compile(
        r"(?:修改|变更|写入|删除)[^\n]{0,120}(?:前|之前)[^\n]{0,40}"
        r"(?:必须|需要|应当|务必)?[^\n]{0,40}"
        r"(?:征得|获得|取得|得到)?(?:用户)?(?:明确)?(?:同意|批准|授权|许可|允许|确认)"
    ),
    re.compile(
        r"(?:必须|需要|应当|务必|应先)[^\n]{0,60}"
        r"(?:征得|获得|取得|得到)?(?:用户)?(?:明确)?(?:同意|批准|授权|许可|允许|确认)"
        r"[^\n]{0,100}(?:再|之后|后|方可|才能|才可)?[^\n]{0,40}"
        r"(?:修改|变更|写入|删除)"
    ),
    re.compile(
        r"(?:must\s+not|do\s+not|may\s+not|cannot)[^\n]{0,120}"
        r"(?:modify|change|write|delete)[^\n]{0,120}(?:without|unless)[^\n]{0,80}"
        r"(?:approval|permission|consent|confirmation)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:approval|permission|consent|confirmation)[^\n]{0,80}(?:required|needed)[^\n]{0,80}"
        r"(?:before|prior\s+to)[^\n]{0,80}(?:modify|change|write|delete)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:ask|consult|confirm\s+with|get|obtain)[^\n]{0,80}"
        r"(?:approval|permission|consent|confirmation|the\s+user|me)[^\n]{0,80}"
        r"(?:before|prior\s+to)[^\n]{0,80}(?:modify|change|write|delete)",
        re.IGNORECASE,
    ),
)

PERMISSION_ALERT_MELODY = (
    (659.25, 90, 35),
    (987.77, 140, 50),
    (739.99, 90, 35),
    (1174.66, 230, 120),
    (523.25, 110, 35),
    (880.00, 300, 0),
)

TASK_PATTERN = re.compile(
    r"^\s*-\s*\[([ xX])\]\s*(?:\*\*)?([A-Za-z][A-Za-z0-9_-]*\d+)(?:\*\*)?\s*[：:]?\s*(.+?)\s*$"
)
REQUEST_ID_PATTERN = re.compile(r"^REQ-[A-Za-z0-9][A-Za-z0-9._-]{2,80}$")
ARCHIVE_DIRECTORY_PATTERN = re.compile(r"^\d{14}$")
SHELL_EXECUTABLES = {
    "bash",
    "bash.exe",
    "cmd",
    "cmd.exe",
    "node",
    "node.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "python",
    "python.exe",
    "python3",
    "python3.exe",
    "sh",
    "sh.exe",
}
HIGH_RISK_TOKENS = {
    "clear-disk",
    "del",
    "diskpart",
    "drop",
    "erase",
    "format",
    "git clean",
    "git reset",
    "icacls",
    "msiexec",
    "pkexec",
    "rd",
    "reg",
    "remove-item",
    "rm",
    "rmdir",
    "runas",
    "sc",
    "schtasks",
    "sudo",
    "takeown",
}
MUTABLE_SCRIPT_SUFFIXES = {".bat", ".cmd", ".js", ".ps1", ".py", ".sh"}
SANDBOX_INJECTED_ENTRY_NAMES = {".agents", ".codex", ".git"}
SANDBOX_RECOVERY_KIND = "sandbox_recovery"
SCOPE_EXTENSION_PROTECTED_PARTS = frozenset(
    {".agents", ".codex", ".codex-automation", ".git"}
)
SANDBOX_RECOVERY_MARKERS = (
    "apply_patch",
    "failed to write file",
    "setup refresh had errors",
    "windows sandbox",
    "沙箱 acl",
    "写入权限",
)
PERMISSION_MENU_OPTIONS = (
    ("1", "批准当前请求"),
    ("2", "授权整个计划请求"),
    ("3", "拒绝当前请求"),
)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class TaskState:
    task_id: str
    title: str
    completed: bool


@dataclass(frozen=True)
class PlanTask:
    task_id: str
    title: str
    deliverable: str
    cohesion_key: str
    depends_on: Tuple[str, ...]
    workspace_root: str
    allowed_paths: Tuple[str, ...]
    generated_paths: Tuple[str, ...]
    preconditions: Tuple[str, ...]
    implementation: Tuple[str, ...]
    decision_constraints: Tuple[str, ...]
    non_goals: Tuple[str, ...]
    acceptance: Tuple[str, ...]
    validation: Tuple[str, ...]
    risk: str
    split_reason: str

    def prompt_value(self) -> Dict[str, Any]:
        return {
            "id": self.task_id,
            "title": self.title,
            "deliverable": self.deliverable,
            "depends_on": list(self.depends_on),
            "workspace_root": self.workspace_root,
            "allowed_paths": list(self.allowed_paths),
            "generated_paths": list(self.generated_paths),
            "preconditions": list(self.preconditions),
            "implementation": list(self.implementation),
            "decision_constraints": list(self.decision_constraints),
            "non_goals": list(self.non_goals),
            "acceptance": list(self.acceptance),
            "validation": list(self.validation),
            "risk": self.risk,
        }


@dataclass(frozen=True)
class PlanSnapshot:
    tasks: Tuple[PlanTask, ...]
    digest: str

    def task(self, task_id: str) -> PlanTask:
        return next(task for task in self.tasks if task.task_id == task_id)


@dataclass(frozen=True)
class StateSnapshot:
    tasks: Tuple[TaskState, ...]
    digest: str
    has_completion_marker: bool

    @property
    def completed_count(self) -> int:
        return sum(task.completed for task in self.tasks)

    @property
    def next_task(self) -> Optional[TaskState]:
        return next((task for task in self.tasks if not task.completed), None)


@dataclass(frozen=True)
class AuthorizationContext:
    files: Tuple[Path, ...]
    matches: Tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class RetrySummary:
    changed_paths: Tuple[str, ...] = ()
    last_failed_command: str = ""
    core_error: str = ""
    final_message: str = ""


@dataclass(frozen=True)
class ProcessResult:
    return_code: int
    timed_out: bool
    timeout_reason: Optional[str]
    duration_seconds: float
    log_file: Path
    output_tail: str
    retry_summary: RetrySummary


class ProcessStartError(RuntimeError):
    def __init__(self, error: OSError) -> None:
        super().__init__(f"{type(error).__name__}: {error}")
        self.error = error


@dataclass(frozen=True)
class WorkspaceEntry:
    kind: str
    digest: str = ""
    link_target: str = ""


@dataclass(frozen=True)
class WorkspaceGuard:
    backup_directory: Path
    roots: Tuple[Path, ...]
    allowed_patterns: Tuple[str, ...]
    excluded_roots: Tuple[Path, ...]
    entries: Dict[str, WorkspaceEntry]


@dataclass(frozen=True)
class AclBackupEntry:
    root: Path
    backup_file: Path


@dataclass(frozen=True)
class AclBackup:
    directory: Path
    entries: Tuple[AclBackupEntry, ...]


class PermissionExecutableError(ValueError):
    def __init__(self, executable: str, cwd: Path, reason: str) -> None:
        self.executable = executable
        self.cwd = cwd
        self.failure_kind = "executable_not_found"
        super().__init__(reason)


class AuthorizationDeniedError(RuntimeError):
    pass


class InteractiveInputUnavailableError(RuntimeError):
    pass


class ConfirmationMismatchError(RuntimeError):
    pass


def read_terminal_input(prompt: str = "") -> str:
    try:
        return input(prompt)
    except EOFError as error:
        raise InteractiveInputUnavailableError(
            "当前终端输入流已关闭，权限请求仍保留并等待人工批准"
        ) from error


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def print_color(text: str, color: str) -> None:
    safe_print(f"{color}{text}{Colors.RESET}", flush=True)


def build_permission_alert_sound() -> bytes:
    sample_rate = 22050
    samples = bytearray()
    for frequency, duration_ms, gap_ms in PERMISSION_ALERT_MELODY:
        frame_count = int(sample_rate * duration_ms / 1000)
        attack_frames = max(1, int(sample_rate * 0.012))
        release_frames = max(1, int(sample_rate * 0.035))
        for frame_index in range(frame_count):
            elapsed_seconds = frame_index / sample_rate
            angle = 2 * math.pi * frequency * elapsed_seconds
            attack = min(1.0, frame_index / attack_frames)
            release = min(1.0, (frame_count - frame_index - 1) / release_frames)
            envelope = max(0.0, min(attack, release))
            tone = (
                math.sin(angle)
                + 0.28 * math.sin(2 * angle)
                + 0.10 * math.sin(3 * angle)
            ) / 1.38
            sample = int(32767 * 0.46 * envelope * tone)
            samples.extend(struct.pack("<h", sample))
        samples.extend(b"\x00\x00" * int(sample_rate * gap_ms / 1000))

    sound_buffer = io.BytesIO()
    with wave.open(sound_buffer, "wb") as sound_file:
        sound_file.setnchannels(1)
        sound_file.setsampwidth(2)
        sound_file.setframerate(sample_rate)
        sound_file.writeframes(samples)
    return sound_buffer.getvalue()


def play_permission_alert() -> None:
    def play() -> None:
        try:
            if os.name == "nt":
                import winsound

                winsound.PlaySound(
                    build_permission_alert_sound(),
                    winsound.SND_MEMORY | winsound.SND_NODEFAULT,
                )
                return
            for _, duration_ms, gap_ms in PERMISSION_ALERT_MELODY:
                safe_print("\a", end="", flush=True)
                time.sleep((duration_ms + gap_ms) / 1000)
        except Exception as error:
            print_color(f"权限提醒声音播放失败：{error}", Colors.RED)

    threading.Thread(target=play, name="permission-alert", daemon=True).start()


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temp_path.write_text(content, encoding="utf-8")
    os.replace(temp_path, path)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temp_path.write_bytes(content)
    os.replace(temp_path, path)


def atomic_write_json(path: Path, value: Dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def ensure_gitignore_rules() -> None:
    if not GITIGNORE_FILE.is_file():
        return
    try:
        raw_content = GITIGNORE_FILE.read_bytes()
        content = raw_content.decode("utf-8-sig")
    except UnicodeDecodeError:
        print_color(".gitignore 不是 UTF-8 编码，已跳过自动更新。", Colors.YELLOW)
        return
    except OSError as error:
        print_color(f"无法读取 .gitignore，已跳过自动更新：{error}", Colors.YELLOW)
        return
    required_rules = ("/.codex-automation/", f"/{SCRIPT_NAME}")
    existing_lines = {line.strip() for line in content.splitlines()}
    missing_rules = [rule for rule in required_rules if rule not in existing_lines]
    if not missing_rules:
        return
    newline = "\r\n" if b"\r\n" in raw_content else "\n"
    additions: List[str] = []
    if "# Autocodex local runtime" not in existing_lines:
        additions.append("# Autocodex local runtime")
    additions.extend(missing_rules)
    separator = "" if not content or content.endswith(("\n", "\r")) else newline
    if content and content.strip() and not content.endswith((newline + newline, "\n\n", "\r\n\r\n")):
        separator += newline
    updated_content = content + separator + newline.join(additions) + newline
    encoded_content = updated_content.encode("utf-8")
    if raw_content.startswith(b"\xef\xbb\xbf"):
        encoded_content = b"\xef\xbb\xbf" + encoded_content
    try:
        atomic_write_bytes(GITIGNORE_FILE, encoded_content)
    except OSError as error:
        print_color(f"无法更新 .gitignore，已继续运行：{error}", Colors.YELLOW)
        return
    print_color("已将 Autocodex 本地运行文件加入 .gitignore。", Colors.GREEN)


def read_json(path: Path, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{path.name} 必须是普通文件")
    if not path.exists():
        return {} if default is None else dict(default)
    if not path.is_file():
        raise ValueError(f"{path.name} 必须是普通文件")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} 的根节点必须是 JSON 对象")
    return value


def update_run_state(**changes: Any) -> Dict[str, Any]:
    state = read_json(
        RUN_STATE_FILE,
        {
            "version": 1,
            "status": "IDLE",
            "created_at": now_iso(),
            "consecutive_failures": 0,
            "consecutive_no_progress": 0,
            "pending_permission_result": None,
        },
    )
    state.update(changes)
    state["updated_at"] = now_iso()
    atomic_write_json(RUN_STATE_FILE, state)
    return state


def ensure_runtime_directories() -> None:
    for path in (
        AUTOMATION_DIR,
        PLANNING_DIR,
        WORKER_CONTROL_DIR,
        LOG_DIR,
        PERMISSION_ARCHIVE_DIR,
        TEMP_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def cleanup_runtime_temp() -> None:
    temp_root = TEMP_DIR.resolve()
    stale_before = time.time() - TEMP_ENTRY_STALE_SECONDS
    for path in TEMP_DIR.iterdir():
        if path.parent.resolve() != temp_root:
            raise RuntimeError(f"拒绝清理临时目录直接子项之外的路径：{path}")
        if path.lstat().st_mtime > stale_before:
            continue
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)


def remove_owned_temp_path(path: Path, expected_parent: Path) -> None:
    if path.parent.resolve() != expected_parent.resolve():
        raise RuntimeError(f"拒绝清理预期临时目录之外的路径：{path}")
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def remove_owned_temp_path_best_effort(path: Path, expected_parent: Path) -> Optional[OSError]:
    cleanup_error: Optional[OSError] = None
    for retry_delay_seconds in (0.0, 0.25, 0.75, 1.5, 3.0, 5.0):
        if retry_delay_seconds:
            time.sleep(retry_delay_seconds)
        try:
            remove_owned_temp_path(path, expected_parent)
        except OSError as error:
            cleanup_error = error
        else:
            return None
    return cleanup_error


def is_archive_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink() and ARCHIVE_DIRECTORY_PATTERN.fullmatch(path.name) is not None


def path_has_content(path: Path) -> bool:
    if path.is_symlink():
        return True
    if path.is_file():
        return path.stat().st_size > 0
    if path.is_dir():
        return next(path.iterdir(), None) is not None
    return False


def unarchived_round_entries() -> List[Path]:
    if not AUTOMATION_DIR.exists():
        return []
    entries: List[Path] = []
    for path in AUTOMATION_DIR.iterdir():
        if path in {
            SUPERVISOR_LOCK_FILE,
            SUPERVISOR_METADATA_FILE,
            APPROVAL_CLAIM_FILE,
        } or is_archive_directory(path):
            continue
        entries.append(path)
    return sorted(entries, key=lambda path: path.name.lower())


def planning_documents_are_nonempty() -> bool:
    for path in (RULES_FILE, PLAN_FILE, STATE_FILE):
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            return False
    return True


def assert_automation_child(path: Path) -> None:
    automation_root = AUTOMATION_DIR.resolve()
    if path.parent.resolve() != automation_root:
        raise RuntimeError(f"拒绝处理自动化目录直接子项之外的路径：{path}")


def remove_active_round(entries: Sequence[Path]) -> None:
    for path in entries:
        assert_automation_child(path)
        if is_archive_directory(path):
            raise RuntimeError(f"拒绝删除归档目录：{path.name}")
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)


def archive_active_round(entries: Sequence[Path]) -> Path:
    while True:
        archive_directory = AUTOMATION_DIR / datetime.now().strftime("%Y%m%d%H%M%S")
        if not archive_directory.exists():
            break
        time.sleep(1)
    archive_directory.mkdir(parents=False)
    try:
        for path in entries:
            assert_automation_child(path)
            if is_archive_directory(path):
                raise RuntimeError(f"拒绝重复归档已有归档目录：{path.name}")
            shutil.move(str(path), str(archive_directory / path.name))
    except Exception:
        if not any(archive_directory.iterdir()):
            archive_directory.rmdir()
        raise
    return archive_directory


def prompt_previous_round_action(can_archive: bool) -> str:
    if not sys.stdin.isatty():
        raise RuntimeError("发现上轮任务文件，需要在交互式终端选择归档或删除")
    if can_archive:
        print_color("检测到已经完成的上轮任务文件：", Colors.YELLOW)
        safe_print("  1. 归档：移动到 .codex-automation/年月日时分秒/", flush=True)
        safe_print("  2. 删除：只删除当前未归档内容，保留所有历史归档", flush=True)
        allowed = {"1": "archive", "2": "delete"}
    else:
        print_color("上轮任务文件不齐全或存在空文件，不能归档。", Colors.RED)
        safe_print("  1. 删除：只删除当前未归档内容，保留所有历史归档", flush=True)
        allowed = {"1": "delete"}
    while True:
        choice = read_terminal_input("请选择：").strip()
        if choice in allowed:
            return allowed[choice]
        print_color(f"请输入 {' 或 '.join(allowed)}。", Colors.YELLOW)


def prepare_previous_round() -> None:
    entries = unarchived_round_entries()
    runtime_directories = {
        PLANNING_DIR,
        WORKER_CONTROL_DIR,
        LOG_DIR,
        PERMISSION_ARCHIVE_DIR,
        TEMP_DIR,
    }
    if not any(path not in runtime_directories or path_has_content(path) for path in entries):
        return
    can_archive = False
    if planning_documents_are_nonempty():
        try:
            snapshot = validate_planning_documents()
        except (OSError, ValueError):
            snapshot = None
        if snapshot is not None and snapshot.next_task is not None:
            return
        can_archive = snapshot is not None and snapshot.next_task is None
    action = prompt_previous_round_action(can_archive)
    if action == "archive":
        archive_directory = archive_active_round(entries)
        print_color(f"上轮任务已归档至 {archive_directory.relative_to(SCRIPT_DIR)}。", Colors.GREEN)
    else:
        remove_active_round(entries)
        print_color("当前未归档轮次已删除，历史归档保持不变。", Colors.GREEN)
    ensure_runtime_directories()


def parse_state_file() -> StateSnapshot:
    if not STATE_FILE.exists():
        raise FileNotFoundError("缺少 STATE.md")
    if STATE_FILE.is_symlink() or not STATE_FILE.is_file():
        raise ValueError("STATE.md 必须是普通文件")
    content = STATE_FILE.read_text(encoding="utf-8")
    tasks: List[TaskState] = []
    seen_ids = set()
    for line in content.splitlines():
        match = TASK_PATTERN.match(line)
        if not match:
            continue
        completed_marker, task_id, title = match.groups()
        if task_id in seen_ids:
            raise ValueError(f"STATE.md 存在重复任务编号：{task_id}")
        seen_ids.add(task_id)
        tasks.append(TaskState(task_id, title.strip(), completed_marker.lower() == "x"))
    if not tasks:
        raise ValueError("STATE.md 中没有可识别的任务复选框")
    lines = content.splitlines()
    marker_indexes = [index for index, line in enumerate(lines) if line.strip() == ALL_COMPLETED]
    if len(marker_indexes) > 1 or (marker_indexes and marker_indexes[0] != len(lines) - 1):
        raise ValueError(f"STATE.md 中的 {ALL_COMPLETED} 只能在末尾出现一次")
    has_marker = bool(marker_indexes)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return StateSnapshot(tuple(tasks), digest, has_marker)


def required_string(value: Any, field_name: str, task_id: str = "") -> str:
    if not isinstance(value, str) or not value.strip():
        prefix = f"任务 {task_id} " if task_id else ""
        raise ValueError(f"{prefix}{field_name} 必须是非空字符串")
    return value.strip()


def required_string_tuple(value: Any, field_name: str, task_id: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"任务 {task_id} {field_name} 必须是非空字符串数组")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"任务 {task_id} {field_name} 只能包含非空字符串")
    return tuple(item.strip() for item in value)


def optional_string_tuple(value: Any, field_name: str, task_id: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"任务 {task_id} {field_name} 必须是字符串数组")
    return tuple(item.strip() for item in value)


def explicit_string_tuple(value: Any, field_name: str, task_id: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"任务 {task_id} {field_name} 必须是字符串数组")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"任务 {task_id} {field_name} 只能包含非空字符串")
    return tuple(item.strip() for item in value)


def validate_decision_constraints(task_id: str, constraints: Tuple[str, ...]) -> None:
    required_prefixes = ("必须：", "禁止：", "冲突时：")
    missing = [prefix for prefix in required_prefixes if not any(item.startswith(prefix) for item in constraints)]
    if missing:
        raise ValueError(
            f"任务 {task_id} decision_constraints 缺少约束类型：{', '.join(missing)}"
        )
    generic_values = {
        "必须：遵循现有架构",
        "必须：遵循项目规则",
        "禁止：自由发挥",
        "禁止：修改无关代码",
        "冲突时：请求用户确认",
    }
    invalid = [item for item in constraints if item in generic_values or len(item.partition("：")[2].strip()) < 8]
    if invalid:
        raise ValueError(
            f"任务 {task_id} decision_constraints 必须引用具体文件、符号、API 、行为，"
            f"不能使用泛化约束：{invalid[0]}"
        )


def extract_plan_data(content: str) -> Dict[str, Any]:
    start = content.find(PLAN_DATA_START)
    end = content.find(PLAN_DATA_END)
    if start < 0 or end < 0 or end <= start:
        raise ValueError("PLAN.md 缺少 AUTOCODEX_PLAN 机器数据块")
    payload = content[start + len(PLAN_DATA_START) : end].strip()
    if payload.startswith("```json") and payload.endswith("```"):
        payload = payload[len("```json") : -len("```")].strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError(f"PLAN.md 机器数据块不是有效 JSON：{error}") from error
    if not isinstance(value, dict):
        raise ValueError("PLAN.md 机器数据块根节点必须是 JSON 对象")
    return value


def replace_plan_data(content: str, value: Dict[str, Any]) -> str:
    start = content.find(PLAN_DATA_START)
    end = content.find(PLAN_DATA_END)
    if start < 0 or end < 0 or end <= start:
        raise ValueError("PLAN.md 缺少 AUTOCODEX_PLAN 机器数据块")
    payload_start = start + len(PLAN_DATA_START)
    payload = json.dumps(value, ensure_ascii=False, indent=2)
    return f"{content[:payload_start]}\n{payload}\n{content[end:]}"


def parse_plan_file(plan_file: Optional[Path] = None) -> PlanSnapshot:
    active_plan_file = PLAN_FILE if plan_file is None else plan_file
    if not active_plan_file.exists():
        raise FileNotFoundError("缺少 PLAN.md")
    if active_plan_file.is_symlink() or not active_plan_file.is_file():
        raise ValueError("PLAN.md 必须是普通文件")
    content = active_plan_file.read_text(encoding="utf-8")
    value = extract_plan_data(content)
    if value.get("version") != PLAN_FORMAT_VERSION:
        raise ValueError(f"PLAN.md 机器数据块 version 必须为 {PLAN_FORMAT_VERSION}")
    raw_tasks = value.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ValueError("PLAN.md 机器数据块 tasks 必须是非空数组")
    tasks: List[PlanTask] = []
    seen_ids = set()
    seen_cohesion_keys = set()
    for raw_task in raw_tasks:
        if not isinstance(raw_task, dict):
            raise ValueError("PLAN.md tasks 只能包含 JSON 对象")
        task_id = required_string(raw_task.get("id"), "id")
        if not re.fullmatch(r"T[0-9]+", task_id):
            raise ValueError(f"PLAN.md 任务编号格式无效：{task_id}")
        if task_id in seen_ids:
            raise ValueError(f"PLAN.md 存在重复任务编号：{task_id}")
        cohesion_key = required_string(raw_task.get("cohesion_key"), "cohesion_key", task_id)
        if cohesion_key in seen_cohesion_keys:
            raise ValueError(f"PLAN.md cohesion_key 重复，相关工作必须合并：{cohesion_key}")
        depends_on = optional_string_tuple(raw_task.get("depends_on"), "depends_on", task_id)
        unknown_dependencies = [dependency for dependency in depends_on if dependency not in seen_ids]
        if unknown_dependencies:
            raise ValueError(
                f"任务 {task_id} 依赖不存在或尚未排在前面：{', '.join(unknown_dependencies)}"
            )
        task = PlanTask(
            task_id=task_id,
            title=required_string(raw_task.get("title"), "title", task_id),
            deliverable=required_string(raw_task.get("deliverable"), "deliverable", task_id),
            cohesion_key=cohesion_key,
            depends_on=depends_on,
            workspace_root=required_string(raw_task.get("workspace_root"), "workspace_root", task_id),
            allowed_paths=explicit_string_tuple(raw_task.get("allowed_paths"), "allowed_paths", task_id),
            generated_paths=explicit_string_tuple(
                raw_task.get("generated_paths"), "generated_paths", task_id
            ),
            preconditions=required_string_tuple(raw_task.get("preconditions"), "preconditions", task_id),
            implementation=required_string_tuple(raw_task.get("implementation"), "implementation", task_id),
            decision_constraints=required_string_tuple(
                raw_task.get("decision_constraints"), "decision_constraints", task_id
            ),
            non_goals=required_string_tuple(raw_task.get("non_goals"), "non_goals", task_id),
            acceptance=required_string_tuple(raw_task.get("acceptance"), "acceptance", task_id),
            validation=required_string_tuple(raw_task.get("validation"), "validation", task_id),
            risk=required_string(raw_task.get("risk"), "risk", task_id),
            split_reason=str(raw_task.get("split_reason", "")).strip(),
        )
        validate_plan_task_paths(task)
        validate_decision_constraints(task_id, task.decision_constraints)
        if re.match(r"^(测试|验证|断言)", task.title) and len(task.acceptance) == 1 and not task.split_reason:
            raise ValueError(
                f"任务 {task_id} 是单断言测试任务，应并入同一交付物的验收矩阵，或填写 split_reason"
            )
        if tasks:
            previous = tasks[-1]
            same_scope = (
                previous.workspace_root == task.workspace_root
                and set(previous.allowed_paths) == set(task.allowed_paths)
                and set(previous.generated_paths) == set(task.generated_paths)
            )
            same_validation = set(previous.validation) == set(task.validation)
            direct_chain = previous.task_id in task.depends_on
            if same_scope and same_validation and direct_chain and not task.split_reason:
                raise ValueError(
                    f"任务 {previous.task_id} 与 {task_id} 修改范围和验证完全相同且线性依赖，"
                    "应合并为一个内聚任务，或为后者填写 split_reason"
                )
        tasks.append(task)
        seen_ids.add(task_id)
        seen_cohesion_keys.add(cohesion_key)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return PlanSnapshot(tuple(tasks), digest)


def render_state_content(plan: PlanSnapshot) -> str:
    lines = [
        "# 自动化任务状态",
        "",
        "每轮只完成一个满足依赖的任务，实现、验收、必要验证全部通过后才能勾选。",
        "不得由工作代理写入 [ALL_COMPLETED]，该标志只由外层监督脚本写入。",
        "",
    ]
    lines.extend(f"- [ ] **{task.task_id}**：{task.title}" for task in plan.tasks)
    return "\n".join(lines) + "\n"


def render_state_file(plan: PlanSnapshot, state_file: Optional[Path] = None) -> None:
    active_state_file = STATE_FILE if state_file is None else state_file
    atomic_write_text(active_state_file, render_state_content(plan))


def read_rules_file() -> str:
    if RULES_FILE.is_symlink() or not RULES_FILE.is_file():
        raise ValueError("RULES.md 必须是普通文件")
    try:
        content = RULES_FILE.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("RULES.md 必须是 UTF-8 编码") from error
    if not content.strip():
        raise ValueError("RULES.md 不能为空")
    return content.strip()


def validate_planning_documents() -> StateSnapshot:
    missing = [path.name for path in (RULES_FILE, PLAN_FILE, STATE_FILE) if not path.exists()]
    if missing:
        raise FileNotFoundError(f"缺少规划文件：{', '.join(missing)}")
    invalid_types = [
        path.name
        for path in (RULES_FILE, PLAN_FILE, STATE_FILE)
        if path.is_symlink() or not path.is_file()
    ]
    if invalid_types:
        raise ValueError(f"规划文件必须是普通文件：{', '.join(invalid_types)}")
    read_rules_file()
    snapshot = parse_state_file()
    plan = parse_plan_file()
    plan_identity = tuple((task.task_id, task.title) for task in plan.tasks)
    state_identity = tuple((task.task_id, task.title) for task in snapshot.tasks)
    if state_identity != plan_identity:
        raise ValueError("STATE.md 的任务编号、标题、顺序与 PLAN.md 机器数据块不一致")
    first_incomplete_index = next(
        (index for index, task in enumerate(snapshot.tasks) if not task.completed),
        len(snapshot.tasks),
    )
    completed_after_gap = [
        task.task_id for task in snapshot.tasks[first_incomplete_index + 1 :] if task.completed
    ]
    if completed_after_gap:
        raise ValueError(
            "STATE.md 的已完成任务必须构成连续前缀，发现越序完成："
            f"{', '.join(completed_after_gap)}"
        )
    if snapshot.has_completion_marker and snapshot.next_task is not None:
        raise ValueError("STATE.md 提前写入 [ALL_COMPLETED]，但仍有未完成任务")
    return snapshot


def state_content_after_task_completion(content: str, task_id: str) -> str:
    updated_lines: List[str] = []
    matched = False
    for line in content.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        match = TASK_PATTERN.match(body)
        if match is None or match.group(2) != task_id:
            updated_lines.append(line)
            continue
        if matched:
            raise ValueError(f"STATE.md 存在重复任务编号：{task_id}")
        if match.group(1).lower() == "x":
            raise ValueError(f"STATE.md 当前任务已经完成：{task_id}")
        marker = re.search(r"\[([ xX])\]", body)
        if marker is None:
            raise ValueError(f"STATE.md 无法定位任务复选框：{task_id}")
        marker_index = marker.start(1)
        updated_lines.append(f"{body[:marker_index]}x{body[marker_index + 1 :]}{ending}")
        matched = True
    if not matched:
        raise ValueError(f"STATE.md 缺少当前任务：{task_id}")
    return "".join(updated_lines)


def restore_file_content(path: Path, expected_content: bytes) -> bool:
    current_content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
    if current_content == expected_content:
        return False
    if path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.exists() and not path.is_file():
        shutil.rmtree(path)
    atomic_write_bytes(path, expected_content)
    return True


def optional_file_content(path: Path) -> Optional[bytes]:
    return path.read_bytes() if path.is_file() and not path.is_symlink() else None


def capture_optional_file_content(path: Path) -> Optional[bytes]:
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ValueError(f"受保护控制文件必须是普通文件或不存在文件：{path.name}")
    return optional_file_content(path)


def optional_file_changed(path: Path, expected_content: Optional[bytes]) -> bool:
    if path.is_symlink() or path.exists() and not path.is_file():
        return True
    return optional_file_content(path) != expected_content


def restore_optional_file_content(path: Path, expected_content: Optional[bytes]) -> bool:
    if not optional_file_changed(path, expected_content):
        return False
    if path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.exists() and not path.is_file():
        raise RuntimeError(f"拒绝用文件恢复逻辑删除目录：{path}")
    if expected_content is None:
        if path.is_file():
            path.unlink(missing_ok=True)
    else:
        if path in {SUPERVISOR_LOCK_FILE, APPROVAL_CLAIM_FILE} and path.is_file():
            path.write_bytes(expected_content)
        else:
            atomic_write_bytes(path, expected_content)
    return True


def restore_changed_optional_files(
    snapshot: Dict[Path, Optional[bytes]],
) -> Tuple[Path, ...]:
    changed = tuple(
        path for path, content in snapshot.items() if optional_file_changed(path, content)
    )
    for path, content in snapshot.items():
        restore_optional_file_content(path, content)
    return changed


def normalize_project_pattern(value: str, field_name: str) -> str:
    normalized = value.strip().replace("\\", "/")
    if (
        not normalized
        or "\0" in normalized
        or "://" in normalized
        or normalized.startswith("/")
        or Path(normalized).is_absolute()
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise ValueError(f"{field_name} 必须是项目内相对路径：{value}")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.rstrip("/")
    if not normalized:
        raise ValueError(f"{field_name} 必须是项目内相对路径")
    if any(part == ".." for part in normalized.split("/")):
        raise ValueError(f"{field_name} 不允许越出项目目录：{value}")
    return normalized


def task_target_directory(allowed_path: str) -> Path:
    normalized = normalize_project_pattern(allowed_path, "allowed_paths")
    if normalized == ".codex-automation" or normalized.startswith(".codex-automation/"):
        raise ValueError(f"allowed_paths 不允许包含监督器目录：{allowed_path}")
    parts = normalized.split("/")
    if any(any(character in part for character in "*?[") for part in parts):
        raise ValueError(f"allowed_paths 只能包含精确文件路径：{allowed_path}")
    target = (SCRIPT_DIR / Path(*parts)).resolve()
    if target.is_dir():
        raise ValueError(f"allowed_paths 只能包含文件，目录树请写入 generated_paths：{allowed_path}")
    directory = target.parent
    project_root = SCRIPT_DIR.resolve()
    if not path_is_within(directory, project_root):
        raise ValueError(f"allowed_paths 越出项目目录：{allowed_path}")
    while not directory.exists() and directory != project_root:
        directory = directory.parent
    if not directory.is_dir():
        raise ValueError(f"无法解析 allowed_paths 的目标目录：{allowed_path}")
    return directory


def workspace_root_path(task: PlanTask) -> Path:
    normalized = normalize_project_pattern(task.workspace_root, "workspace_root")
    if any(character in normalized for character in "*?["):
        raise ValueError(f"任务 {task.task_id} workspace_root 不允许通配符")
    if normalized == ".codex-automation" or normalized.startswith(".codex-automation/"):
        raise ValueError(f"任务 {task.task_id} workspace_root 不允许指向监督器目录")
    root = (SCRIPT_DIR / Path(*normalized.split("/"))).resolve()
    if not path_is_within(root, SCRIPT_DIR.resolve()):
        raise ValueError(f"任务 {task.task_id} workspace_root 越出项目目录")
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"任务 {task.task_id} workspace_root 必须是现有普通目录：{normalized}")
    return root


def generated_path_root(generated_path: str, task_id: str = "") -> Path:
    normalized = normalize_project_pattern(generated_path, "generated_paths")
    if not normalized.endswith("/**"):
        raise ValueError(f"任务 {task_id} generated_paths 必须使用精确的 path/**：{generated_path}")
    prefix = normalized[:-3].rstrip("/")
    if not prefix or any(character in prefix for character in "*?["):
        raise ValueError(f"任务 {task_id} generated_paths 的目录部分不允许通配符：{generated_path}")
    if prefix == ".codex-automation" or prefix.startswith(".codex-automation/"):
        raise ValueError(f"任务 {task_id} generated_paths 不允许包含监督器目录")
    root = (SCRIPT_DIR / Path(*prefix.split("/"))).resolve()
    if not path_is_within(root, SCRIPT_DIR.resolve()):
        raise ValueError(f"任务 {task_id} generated_paths 越出项目目录：{generated_path}")
    return root


def validate_plan_task_paths(task: PlanTask) -> None:
    workspace_root = workspace_root_path(task)
    normalized_allowed: set[str] = set()
    for allowed_path in task.allowed_paths:
        normalized = normalize_project_pattern(allowed_path, "allowed_paths")
        task_target_directory(normalized)
        comparable = normalized_match_value(normalized)
        if comparable in normalized_allowed:
            raise ValueError(f"任务 {task.task_id} allowed_paths 不允许重复：{normalized}")
        normalized_allowed.add(comparable)
        target = (SCRIPT_DIR / Path(*normalized.split("/"))).resolve()
        if not path_is_within(target, workspace_root):
            raise ValueError(
                f"任务 {task.task_id} allowed_paths 必须位于 workspace_root 内：{normalized}"
            )
    normalized_generated: set[str] = set()
    for generated_path in task.generated_paths:
        root = generated_path_root(generated_path, task.task_id)
        normalized = normalize_project_pattern(generated_path, "generated_paths")
        comparable = normalized_match_value(normalized)
        if comparable in normalized_generated:
            raise ValueError(f"任务 {task.task_id} generated_paths 不允许重复：{normalized}")
        normalized_generated.add(comparable)
        for allowed_path in task.allowed_paths:
            allowed_target = (SCRIPT_DIR / Path(*normalize_project_pattern(
                allowed_path, "allowed_paths"
            ).split("/"))).resolve()
            if path_is_within(allowed_target, root):
                raise ValueError(
                    f"任务 {task.task_id} allowed_paths 不得位于 generated_paths 内：{allowed_path}"
                )


def task_writable_roots(task: PlanTask) -> Tuple[Path, ...]:
    candidate_roots = sorted(
        {task_target_directory(path).resolve() for path in task.allowed_paths},
        key=lambda path: (len(path.parts), str(path).casefold()),
    )
    roots: List[Path] = []
    for candidate in candidate_roots:
        if any(path_is_within(candidate, root) for root in roots):
            continue
        roots.append(candidate)
    return tuple(roots)


def task_primary_workspace(task: PlanTask, fallback: Path) -> Path:
    del task
    return fallback


def generated_output_roots(task: PlanTask) -> Tuple[Path, ...]:
    roots = {generated_path_root(path, task.task_id) for path in task.generated_paths}
    return tuple(sorted(roots, key=lambda path: str(path).casefold()))


def task_guard_patterns(task: PlanTask) -> Tuple[str, ...]:
    return (*task.allowed_paths, *task.generated_paths)


def cleanup_generated_sandbox_metadata(roots: Sequence[Path]) -> Tuple[str, ...]:
    cleaned: List[str] = []
    project_root = SCRIPT_DIR.resolve()
    for root in roots:
        resolved_root = root.resolve()
        if not path_is_within(resolved_root, project_root):
            raise RuntimeError(f"拒绝清理项目外的沙箱元数据：{resolved_root}")
        for entry_name in SANDBOX_INJECTED_ENTRY_NAMES:
            artifact = resolved_root / entry_name
            if not artifact.exists() and not artifact.is_symlink():
                continue
            if artifact.is_symlink() or not artifact.is_dir():
                raise RuntimeError(f"沙箱元数据路径类型异常，拒绝自动清理：{artifact}")
            if next(artifact.iterdir(), None) is not None:
                raise RuntimeError(f"沙箱元数据目录非空，拒绝自动清理：{artifact}")
            artifact.rmdir()
            cleaned.append(project_relative_path(artifact))
    return tuple(cleaned)


def normalized_distinct_roots(roots: Sequence[Path]) -> Tuple[Path, ...]:
    resolved_roots = sorted(
        {root.resolve() for root in roots},
        key=lambda path: (len(path.parts), str(path).casefold()),
    )
    distinct: List[Path] = []
    for root in resolved_roots:
        if any(path_is_within(root, parent) for parent in distinct):
            continue
        distinct.append(root)
    return tuple(distinct)


def run_icacls(arguments: Sequence[str], cwd: Path) -> str:
    executable = shutil.which("icacls")
    if executable is None:
        raise RuntimeError("找不到 Windows icacls，无法安全管理沙箱 ACL")
    result = subprocess.run(
        [executable, *arguments],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=300,
    )
    output = normalized_console_text(result.stdout)
    if result.returncode != 0:
        detail = f"：{compact_console_text(output, 1000)}" if output else ""
        raise RuntimeError(f"icacls 执行失败（退出码 {result.returncode}）{detail}")
    return output


def configure_windows_security_apis() -> Tuple[Any, Any]:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        pointer,
        pointer,
        pointer,
        pointer,
        pointer,
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        pointer,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        pointer,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return advapi32, kernel32


def windows_dacl_sddl(path: Path) -> str:
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = configure_windows_security_apis()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000004,
        None,
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise ctypes.WinError(result)
    sddl = wintypes.LPWSTR()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            1,
            0x00000004,
            ctypes.byref(sddl),
            None,
        ):
            raise ctypes.WinError()
        return sddl.value
    finally:
        if sddl:
            kernel32.LocalFree(ctypes.cast(sddl, ctypes.c_void_p))
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def windows_owner_account(path: Path) -> str:
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = configure_windows_security_apis()
    owner_sid = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,
        0x00000001,
        ctypes.byref(owner_sid),
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise ctypes.WinError(result)
    try:
        name_size = wintypes.DWORD()
        domain_size = wintypes.DWORD()
        sid_type = wintypes.DWORD()
        advapi32.LookupAccountSidW(
            None,
            owner_sid,
            None,
            ctypes.byref(name_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        )
        if ctypes.get_last_error() != 122:
            raise ctypes.WinError(ctypes.get_last_error())
        name = ctypes.create_unicode_buffer(name_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not advapi32.LookupAccountSidW(
            None,
            owner_sid,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return f"{domain.value}\\{name.value}" if domain.value else name.value
    finally:
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def is_codex_sandbox_owner(account: str) -> bool:
    return account.rsplit("\\", 1)[-1].casefold() in {
        "codexsandboxoffline",
        "codexsandboxonline",
    }


def restore_windows_dacl(path: Path, sddl: str) -> None:
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = configure_windows_security_apis()
    security_descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(security_descriptor),
        None,
    ):
        raise ctypes.WinError()
    dacl_present = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()
    dacl = ctypes.c_void_p()
    try:
        if not advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            raise ctypes.WinError()
        if not dacl_present.value:
            raise RuntimeError(f"ACL 备份缺少 DACL：{path}")
        dacl_flags = sddl[2:].split("(", 1)[0] if sddl.startswith("D:") else ""
        inheritance_flag = 0x80000000 if "P" in dacl_flags else 0x20000000
        result = advapi32.SetNamedSecurityInfoW(
            str(path),
            1,
            0x00000004 | inheritance_flag,
            None,
            None,
            dacl,
            None,
        )
        if result != 0:
            raise ctypes.WinError(result)
    finally:
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def acl_snapshot_paths(root: Path) -> Tuple[Path, ...]:
    paths = [root]
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names[:] = [
            name for name in directory_names if not (current / name).is_symlink()
        ]
        paths.extend(current / name for name in directory_names)
        paths.extend(
            current / name
            for name in file_names
            if not (current / name).is_symlink()
        )
    return tuple(paths)


def capture_acl_backup(
    roots: Sequence[Path],
    label: str,
    backup_parent: Path = TEMP_DIR,
) -> Optional[AclBackup]:
    if os.name != "nt":
        return None
    entries: List[AclBackupEntry] = []
    backup_directory = backup_parent / f"acl-{label}-{uuid.uuid4().hex[:8]}"
    backup_directory.mkdir(parents=True)
    try:
        for index, root in enumerate(normalized_distinct_roots(roots), start=1):
            if root.is_symlink() or not root.is_dir():
                raise RuntimeError(f"ACL 备份目标必须是现有普通目录：{root}")
            backup_file = backup_directory / f"root-{index}.json"
            snapshot = {
                "version": 1,
                "root": str(root),
                "entries": [
                    {
                        "relative_path": "." if path == root else path.relative_to(root).as_posix(),
                        "dacl_sddl": windows_dacl_sddl(path),
                    }
                    for path in acl_snapshot_paths(root)
                ],
            }
            atomic_write_json(
                backup_file,
                snapshot,
            )
            entries.append(AclBackupEntry(root=root, backup_file=backup_file))
    except Exception:
        shutil.rmtree(backup_directory, ignore_errors=True)
        raise
    return AclBackup(backup_directory, tuple(entries))


def restore_acl_backup(backup: Optional[AclBackup], remove_after_restore: bool = True) -> None:
    if backup is None:
        return
    errors: List[str] = []
    for entry in reversed(backup.entries):
        try:
            snapshot = read_json(entry.backup_file)
            raw_entries = snapshot.get("entries")
            if snapshot.get("version") != 1 or snapshot.get("root") != str(entry.root):
                raise RuntimeError("ACL 备份头无效")
            if not isinstance(raw_entries, list) or not raw_entries:
                raise RuntimeError("ACL 备份内容为空")
            restore_entries: List[Tuple[Path, str]] = []
            for raw_entry in raw_entries:
                if not isinstance(raw_entry, dict):
                    raise RuntimeError("ACL 备份条目格式无效")
                relative_path = raw_entry.get("relative_path")
                dacl_sddl = raw_entry.get("dacl_sddl")
                if not isinstance(relative_path, str) or not isinstance(dacl_sddl, str):
                    raise RuntimeError("ACL 备份条目缺少路径或 DACL")
                target = entry.root if relative_path == "." else entry.root / Path(
                    *relative_path.split("/")
                )
                if not path_is_within(target.resolve(), entry.root) or not target.exists():
                    continue
                restore_entries.append((target, dacl_sddl))
            for target, dacl_sddl in sorted(
                restore_entries,
                key=lambda item: len(item[0].parts),
                reverse=True,
            ):
                try:
                    if windows_dacl_sddl(target) == dacl_sddl:
                        continue
                    restore_windows_dacl(target, dacl_sddl)
                except Exception as error:
                    errors.append(f"{target}: {error}")
        except Exception as error:
            errors.append(f"{entry.root}: {error}")
    if errors:
        raise RuntimeError("ACL 回滚失败；备份已保留在 " + str(backup.directory) + "；" + "；".join(errors))
    if remove_after_restore:
        shutil.rmtree(backup.directory)


def load_acl_backup(directory: Path) -> AclBackup:
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f"ACL 备份目录无效：{directory}")
    entries: List[AclBackupEntry] = []
    for backup_file in sorted(directory.glob("root-*.json"), key=lambda path: path.name):
        snapshot = read_json(backup_file)
        root_value = snapshot.get("root")
        if snapshot.get("version") != 1 or not isinstance(root_value, str):
            raise RuntimeError(f"ACL 备份头无效：{backup_file}")
        root = Path(root_value).resolve()
        if not path_is_within(root, SCRIPT_DIR.resolve()):
            raise RuntimeError(f"ACL 备份目标越出项目目录：{root}")
        entries.append(AclBackupEntry(root=root, backup_file=backup_file))
    if not entries:
        raise RuntimeError(f"ACL 备份目录没有有效条目：{directory}")
    return AclBackup(directory, tuple(entries))


def rollback_interrupted_sandbox_recovery(request: Dict[str, Any]) -> None:
    backup_root = PERMISSION_ARCHIVE_DIR / "acl-backups"
    if not backup_root.is_dir():
        return
    prefix = f"acl-{request['request_id']}-"
    candidates = sorted(
        (
            path
            for path in backup_root.iterdir()
            if path.name.startswith(prefix) and path.is_dir() and not path.is_symlink()
        ),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )
    if not candidates:
        return
    original_backup = load_acl_backup(candidates[0])
    restore_acl_backup(original_backup, remove_after_restore=False)
    for candidate in candidates:
        if candidate.parent.resolve() != backup_root.resolve():
            raise RuntimeError(f"拒绝清理预期目录之外的 ACL 备份：{candidate}")
        shutil.rmtree(candidate)
    print_color("已从首次备份恢复上次中断的 ACL 修改。", Colors.GREEN)


def path_tree_manifest(root: Path) -> str:
    digest = hashlib.sha256()
    stack = [(root, Path("."))]
    while stack:
        path, relative_path = stack.pop()
        relative_value = relative_path.as_posix().encode("utf-8")
        if path.is_symlink():
            digest.update(b"L\0" + relative_value + b"\0")
            digest.update(os.readlink(path).encode("utf-8") + b"\0")
            continue
        if path.is_file():
            digest.update(b"F\0" + relative_value + b"\0")
            digest.update(str(path.stat().st_size).encode("ascii") + b"\0")
            digest.update(file_digest(path).encode("ascii") + b"\0")
            continue
        if not path.is_dir():
            raise RuntimeError(f"所有权恢复只支持普通文件、目录和符号链接：{path}")
        digest.update(b"D\0" + relative_value + b"\0")
        children = sorted(path.iterdir(), key=lambda child: child.name.casefold())
        for child in reversed(children):
            child_relative = Path(child.name) if relative_path == Path(".") else relative_path / child.name
            stack.append((child, child_relative))
    return digest.hexdigest()


def normalize_sandbox_owned_paths(
    roots: Sequence[Path],
    request_id: str,
) -> Tuple[Tuple[str, ...], Optional[Path]]:
    backup_parent = PERMISSION_ARCHIVE_DIR / "ownership-backups"
    backup_directory = backup_parent / f"ownership-{request_id}-{uuid.uuid4().hex[:8]}"
    backup_directory.mkdir(parents=True)
    distinct_roots = normalized_distinct_roots(roots)
    owned_directories: List[Tuple[int, Path, str]] = []
    owned_files: List[Tuple[int, Path, str]] = []
    for root_index, root in enumerate(distinct_roots, start=1):
        for path in acl_snapshot_paths(root):
            if path.is_symlink():
                continue
            owner = windows_owner_account(path)
            if not is_codex_sandbox_owner(owner):
                continue
            if path.is_dir():
                owned_directories.append((root_index, path, owner))
            elif path.is_file():
                owned_files.append((root_index, path, owner))
            else:
                raise RuntimeError(f"沙箱账户拥有非普通文件，拒绝自动处理：{path}")
    selected_directories: List[Tuple[int, Path, str]] = []
    for candidate in sorted(owned_directories, key=lambda item: len(item[1].parts)):
        if any(path_is_within(candidate[1], selected[1]) for selected in selected_directories):
            continue
        selected_directories.append(candidate)
    selected_files = [
        candidate
        for candidate in owned_files
        if not any(path_is_within(candidate[1], directory[1]) for directory in selected_directories)
    ]
    if not selected_directories and not selected_files:
        backup_directory.rmdir()
        return (), None
    staged_directories: List[Tuple[Path, Path]] = []
    staged_files: List[Tuple[Path, Path]] = []
    normalized: List[str] = []
    try:
        for root_index, path, owner in selected_directories:
            root = distinct_roots[root_index - 1]
            relative_path = Path(path.name) if path == root else path.relative_to(root)
            persistent_backup = backup_directory / f"root-{root_index}" / "directories" / relative_path
            original_manifest = path_tree_manifest(path)
            shutil.copytree(path, persistent_backup, symlinks=True, copy_function=shutil.copy2)
            if path_tree_manifest(persistent_backup) != original_manifest:
                raise RuntimeError(f"目录所有权恢复备份清单不一致：{path}")
            staged_original = path.with_name(
                f".{path.name}.{request_id}.{uuid.uuid4().hex[:8]}.owner-backup"
            )
            os.replace(path, staged_original)
            staged_directories.append((path, staged_original))
            shutil.copytree(staged_original, path, symlinks=True, copy_function=shutil.copy2)
            if path_tree_manifest(path) != original_manifest:
                raise RuntimeError(f"目录所有权恢复后清单不一致：{path}")
            new_owner = windows_owner_account(path)
            if is_codex_sandbox_owner(new_owner) or new_owner == owner:
                raise RuntimeError(f"所有权恢复后目录仍属于沙箱账户：{path}")
            normalized.append(project_relative_path(path))
        for root_index, path, owner in selected_files:
            root = distinct_roots[root_index - 1]
            relative_path = Path(path.name) if path == root else path.relative_to(root)
            persistent_backup = backup_directory / f"root-{root_index}" / "files" / relative_path
            persistent_backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, persistent_backup)
            original_digest = file_digest(path)
            if file_digest(persistent_backup) != original_digest:
                raise RuntimeError(f"所有权恢复备份哈希不一致：{path}")
            staged_original = path.with_name(
                f".{path.name}.{request_id}.{uuid.uuid4().hex[:8]}.owner-backup"
            )
            os.replace(path, staged_original)
            staged_files.append((path, staged_original))
            shutil.copy2(staged_original, path)
            if file_digest(path) != original_digest:
                raise RuntimeError(f"所有权恢复后内容哈希不一致：{path}")
            new_owner = windows_owner_account(path)
            if is_codex_sandbox_owner(new_owner) or new_owner == owner:
                raise RuntimeError(f"所有权恢复后文件仍属于沙箱账户：{path}")
            normalized.append(project_relative_path(path))
    except Exception as operation_error:
        rollback_errors: List[str] = []
        for path, staged_original in reversed(staged_files):
            try:
                cleanup_error = remove_owned_temp_path_best_effort(path, path.parent)
                if cleanup_error is not None:
                    raise cleanup_error
                if staged_original.exists():
                    os.replace(staged_original, path)
            except OSError as error:
                rollback_errors.append(f"{path}: {error}")
        for path, staged_original in reversed(staged_directories):
            try:
                cleanup_error = remove_owned_temp_path_best_effort(path, path.parent)
                if cleanup_error is not None:
                    raise cleanup_error
                if staged_original.exists():
                    os.replace(staged_original, path)
            except OSError as error:
                rollback_errors.append(f"{path}: {error}")
        if rollback_errors:
            raise RuntimeError(
                "所有权恢复失败且原件回滚不完整；持久备份已保留在 "
                + str(backup_directory)
                + f"；原错误：{operation_error}；回滚错误："
                + "；".join(rollback_errors)
            ) from operation_error
        raise
    cleanup_errors: List[str] = []
    for _, staged_original in staged_files:
        cleanup_error = remove_owned_temp_path_best_effort(
            staged_original,
            staged_original.parent,
        )
        if cleanup_error is not None:
            cleanup_errors.append(f"{staged_original}: {cleanup_error}")
    for _, staged_original in staged_directories:
        cleanup_error = remove_owned_temp_path_best_effort(
            staged_original,
            staged_original.parent,
        )
        if cleanup_error is not None:
            cleanup_errors.append(f"{staged_original}: {cleanup_error}")
    if cleanup_errors:
        raise RuntimeError(
            "所有权已归还且持久备份已保留，但临时原件清理失败；请停止重试："
            + "；".join(cleanup_errors)
        )
    return tuple(normalized), backup_directory


def existing_task_allowed_files(task: PlanTask) -> Tuple[Path, ...]:
    files: List[Path] = []
    for allowed_path in task.allowed_paths:
        normalized = normalize_project_pattern(allowed_path, "allowed_paths")
        path = SCRIPT_DIR / Path(*normalized.split("/"))
        if path.is_symlink():
            raise RuntimeError(f"allowed_paths 目标不得是符号链接：{normalized}")
        if path.exists() and not path.is_file():
            raise RuntimeError(f"allowed_paths 目标必须是普通文件：{normalized}")
        if path.is_file():
            files.append(path.resolve())
    return tuple(files)


def repair_sandbox_acl(request: Dict[str, Any]) -> Dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("sandbox_recovery 仅适用于 Windows 沙箱")
    state = validate_planning_documents()
    if state.next_task is None or state.next_task.task_id != request["task_id"]:
        raise RuntimeError("沙箱恢复请求不属于当前待执行任务")
    plan = parse_plan_file()
    if request["plan_digest"] != plan.digest:
        raise RuntimeError("沙箱恢复请求对应的 PLAN.md 已发生变化")
    task = plan.task(request["task_id"])
    if request["workspace_root"] != task.workspace_root:
        raise RuntimeError("沙箱恢复请求的 workspace_root 与当前任务不一致")
    allowed = {
        normalized_match_value(normalize_project_pattern(path, "allowed_paths"))
        for path in task.allowed_paths
    }
    targets = {
        normalized_match_value(normalize_project_pattern(path, "targets"))
        for path in request["targets"]
    }
    if not targets or not targets.issubset(allowed):
        raise RuntimeError("沙箱恢复请求包含当前任务 allowed_paths 之外的目标")
    roots = task_writable_roots(task)
    if not roots:
        raise RuntimeError("当前任务没有可恢复的源码写入目录")
    cleaned_metadata = cleanup_generated_sandbox_metadata(roots)
    normalized_paths, ownership_backup = normalize_sandbox_owned_paths(
        roots,
        request["request_id"],
    )
    result = {
        "version": 1,
        "request_id": request["request_id"],
        "task_id": request["task_id"],
        "status": "sandbox_reconfigured",
        "finished_at": now_iso(),
        "repaired_roots": [project_relative_path(root) for root in roots],
        "cleaned_metadata": list(cleaned_metadata),
        "normalized_owners": list(normalized_paths),
        "note": "已备份并原子重建沙箱账户拥有的最外层目录及普通文件，再启用隔离工作目录和最小写入根",
    }
    if ownership_backup is not None:
        result["ownership_backup"] = project_relative_path(ownership_backup)
    return result


def project_relative_path(path: Path) -> str:
    absolute = Path(os.path.abspath(path))
    project_root = Path(os.path.abspath(SCRIPT_DIR))
    try:
        return absolute.relative_to(project_root).as_posix()
    except ValueError as error:
        raise RuntimeError(f"路径不在项目目录内：{path}") from error


def normalized_match_value(value: str) -> str:
    return value.casefold() if os.name == "nt" else value


def path_pattern_matches(candidate: str, pattern: str) -> bool:
    candidate_parts = tuple(candidate.split("/"))
    pattern_parts = tuple(pattern.split("/"))
    cache: Dict[Tuple[int, int], bool] = {}

    def matches(candidate_index: int, pattern_index: int) -> bool:
        key = (candidate_index, pattern_index)
        if key in cache:
            return cache[key]
        if pattern_index == len(pattern_parts):
            result = candidate_index == len(candidate_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(candidate_index, pattern_index + 1) or (
                candidate_index < len(candidate_parts)
                and matches(candidate_index + 1, pattern_index)
            )
        else:
            result = (
                candidate_index < len(candidate_parts)
                and fnmatch.fnmatchcase(candidate_parts[candidate_index], pattern_parts[pattern_index])
                and matches(candidate_index + 1, pattern_index + 1)
            )
        cache[key] = result
        return result

    return matches(0, 0)


def path_can_contain_pattern_match(candidate: str, pattern: str) -> bool:
    candidate_parts = tuple(candidate.split("/"))
    pattern_parts = tuple(pattern.split("/"))
    cache: Dict[Tuple[int, int], bool] = {}

    def matches_prefix(candidate_index: int, pattern_index: int) -> bool:
        key = (candidate_index, pattern_index)
        if key in cache:
            return cache[key]
        if candidate_index == len(candidate_parts):
            result = True
        elif pattern_index == len(pattern_parts):
            result = False
        elif pattern_parts[pattern_index] == "**":
            result = matches_prefix(candidate_index, pattern_index + 1) or matches_prefix(
                candidate_index + 1,
                pattern_index,
            )
        else:
            result = fnmatch.fnmatchcase(
                candidate_parts[candidate_index],
                pattern_parts[pattern_index],
            ) and matches_prefix(candidate_index + 1, pattern_index + 1)
        cache[key] = result
        return result

    return matches_prefix(0, 0)


def path_matches_allowed(relative_path: str, patterns: Sequence[str]) -> bool:
    candidate = normalized_match_value(relative_path.strip("/"))
    for raw_pattern in patterns:
        pattern = normalize_project_pattern(raw_pattern, "allowed_paths")
        comparable_pattern = normalized_match_value(pattern)
        if any(character in pattern for character in "*?["):
            if path_pattern_matches(candidate, comparable_pattern) or path_can_contain_pattern_match(
                candidate,
                comparable_pattern,
            ):
                return True
            continue
        if comparable_pattern.startswith(candidate + "/"):
            return True
        if candidate == comparable_pattern:
            return True
    return False


def iter_workspace_paths(
    roots: Sequence[Path],
    excluded_roots: Sequence[Path] = (),
) -> Iterable[Path]:
    seen: set[str] = set()
    excluded = {Path(os.path.abspath(path)) for path in excluded_roots}
    stack = list(reversed(roots))
    while stack:
        directory = stack.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda path: path.name.casefold())
        except (FileNotFoundError, NotADirectoryError):
            continue
        for path in children:
            absolute = Path(os.path.abspath(path))
            if any(path_is_within(absolute, excluded_root) for excluded_root in excluded):
                continue
            relative = project_relative_path(path)
            comparable = normalized_match_value(relative)
            if comparable in seen:
                continue
            seen.add(comparable)
            yield path
            if path.is_dir() and not path.is_symlink():
                stack.append(path)


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def workspace_entry(path: Path) -> WorkspaceEntry:
    if path.is_symlink():
        kind = "symlink_directory" if path.is_dir() else "symlink"
        return WorkspaceEntry(kind, link_target=os.readlink(path))
    if path.is_dir():
        return WorkspaceEntry("directory")
    if path.is_file():
        return WorkspaceEntry("file", digest=file_digest(path))
    return WorkspaceEntry("other")


def prepare_workspace_guard_backup_root() -> Path:
    if WORKSPACE_GUARD_BACKUP_ROOT.is_symlink():
        raise RuntimeError("工作区保护备份根目录不允许是符号链接")
    WORKSPACE_GUARD_BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    if WORKSPACE_GUARD_BACKUP_ROOT.is_symlink() or not WORKSPACE_GUARD_BACKUP_ROOT.is_dir():
        raise RuntimeError("工作区保护备份根目录必须是普通目录")
    backup_root = WORKSPACE_GUARD_BACKUP_ROOT.resolve()
    if path_is_within(backup_root, SCRIPT_DIR.resolve()):
        raise RuntimeError("系统临时目录位于项目内，无法安全存放工作区保护备份")
    stale_before = time.time() - TEMP_ENTRY_STALE_SECONDS
    for path in backup_root.iterdir():
        if not path.name.startswith("workspace-guard-") or path.lstat().st_mtime > stale_before:
            continue
        remove_owned_temp_path(path, backup_root)
    return backup_root


def capture_workspace_guard(
    roots: Sequence[Path],
    allowed_patterns: Sequence[str],
    excluded_roots: Sequence[Path] = (),
) -> WorkspaceGuard:
    guarded_roots = tuple(
        root
        for root in roots
        if not any(
            normalize_project_pattern(pattern, "allowed_paths")
            == f"{project_relative_path(root).strip('/')}/**"
            for pattern in allowed_patterns
        )
    )
    backup_root = prepare_workspace_guard_backup_root()
    backup_directory = backup_root / f"workspace-guard-{uuid.uuid4().hex}"
    files_directory = backup_directory / "files"
    entries: Dict[str, WorkspaceEntry] = {}
    files_to_backup: List[Tuple[Path, str]] = []
    backup_bytes = 0
    try:
        for path in iter_workspace_paths(guarded_roots, excluded_roots):
            relative = project_relative_path(path)
            if relative != SCRIPT_NAME and path_matches_allowed(relative, allowed_patterns):
                continue
            if path.is_symlink():
                entry = workspace_entry(path)
            elif path.is_file():
                backup_bytes += path.stat().st_size
                if backup_bytes > MAX_WORKSPACE_GUARD_BACKUP_BYTES:
                    raise RuntimeError(
                        "allowed_paths 的可写根过宽，需要备份的范围超过 "
                        f"{MAX_WORKSPACE_GUARD_BACKUP_BYTES // (1024 * 1024)} MiB"
                    )
                files_to_backup.append((path, relative))
                continue
            else:
                entry = workspace_entry(path)
            entries[relative] = entry
        free_space = shutil.disk_usage(backup_root).free
        required_space = backup_bytes + WORKSPACE_GUARD_FREE_SPACE_RESERVE_BYTES
        if required_space > free_space:
            raise RuntimeError(
                "工作区保护备份空间不足："
                f"需要 {required_space // (1024 * 1024)} MiB，"
                f"当前可用 {free_space // (1024 * 1024)} MiB"
            )
        files_directory.mkdir(parents=True)
        for path, relative in files_to_backup:
            backup_path = files_directory / Path(*relative.split("/"))
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup_path)
            entries[relative] = WorkspaceEntry("file", digest=file_digest(backup_path))
    except Exception:
        shutil.rmtree(backup_directory, ignore_errors=True)
        raise
    return WorkspaceGuard(
        backup_directory,
        guarded_roots,
        tuple(allowed_patterns),
        tuple(excluded_roots),
        entries,
    )


def current_guard_entries(guard: WorkspaceGuard) -> Dict[str, WorkspaceEntry]:
    entries: Dict[str, WorkspaceEntry] = {}
    for path in iter_workspace_paths(guard.roots, guard.excluded_roots):
        relative = project_relative_path(path)
        if relative != SCRIPT_NAME and path_matches_allowed(relative, guard.allowed_patterns):
            continue
        entries[relative] = workspace_entry(path)
    return entries


def remove_for_restore(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def restore_file_from_backup(path: Path, backup_path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.restore")
    shutil.copy2(backup_path, temp_path)
    os.replace(temp_path, path)


def sandbox_injected_guard_artifacts(
    guard: WorkspaceGuard,
    violations: Sequence[str],
) -> Tuple[str, ...]:
    sandbox_artifact_roots = {
        f"{project_relative_path(root).strip('/')}/{entry_name}"
        for root in guard.roots
        for entry_name in SANDBOX_INJECTED_ENTRY_NAMES
    }
    return tuple(
        relative
        for relative in violations
        if any(
            artifact_root not in guard.entries
            and (relative == artifact_root or relative.startswith(f"{artifact_root}/"))
            for artifact_root in sandbox_artifact_roots
        )
    )


def restore_workspace_guard(guard: WorkspaceGuard) -> Tuple[str, ...]:
    current_entries = current_guard_entries(guard)
    violations = sorted(
        relative
        for relative in set(guard.entries) | set(current_entries)
        if guard.entries.get(relative) != current_entries.get(relative)
    )
    if not violations:
        shutil.rmtree(guard.backup_directory, ignore_errors=True)
        return ()
    for relative in sorted(violations, key=lambda value: len(Path(value).parts), reverse=True):
        current = current_entries.get(relative)
        expected = guard.entries.get(relative)
        if current is None or current == expected:
            continue
        path = SCRIPT_DIR / Path(*relative.split("/"))
        if current.kind == "directory" and expected is None:
            path.rmdir()
        else:
            remove_for_restore(path)
    for relative in sorted(violations, key=lambda value: len(Path(value).parts)):
        expected = guard.entries.get(relative)
        if expected is None:
            continue
        path = SCRIPT_DIR / Path(*relative.split("/"))
        if expected.kind == "directory":
            path.mkdir(parents=True, exist_ok=True)
        elif expected.kind == "file":
            backup_path = guard.backup_directory / "files" / Path(*relative.split("/"))
            if backup_path.is_symlink() or not backup_path.is_file():
                raise RuntimeError(f"工作区保护备份文件缺失或类型异常：{relative}")
            if file_digest(backup_path) != expected.digest:
                raise RuntimeError(f"工作区保护备份摘要不匹配：{relative}")
            restore_file_from_backup(path, backup_path)
        elif expected.kind in {"symlink", "symlink_directory"}:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink():
                remove_for_restore(path)
            os.symlink(
                expected.link_target,
                path,
                target_is_directory=expected.kind == "symlink_directory",
            )
    ignored_sandbox_artifacts = sandbox_injected_guard_artifacts(guard, violations)
    shutil.rmtree(guard.backup_directory, ignore_errors=True)
    if ignored_sandbox_artifacts:
        print_color(
            "已清理 Codex Windows 沙箱注入的临时元数据目录："
            + ", ".join(ignored_sandbox_artifacts),
            Colors.DARK_GRAY,
        )
    return tuple(relative for relative in violations if relative not in ignored_sandbox_artifacts)


def authorization_rule_files(task: PlanTask) -> Tuple[Path, ...]:
    project_root = SCRIPT_DIR.resolve()
    files: Dict[Path, Path] = {}

    def add_rule_file(candidate: Path) -> None:
        if candidate.is_symlink() or not candidate.is_file():
            return
        files[candidate.resolve()] = candidate

    for allowed_path in task.allowed_paths:
        normalized_pattern = normalize_project_pattern(allowed_path, "allowed_paths")
        target_directory = task_target_directory(allowed_path)
        relative_parts = target_directory.relative_to(project_root).parts
        directory = project_root
        add_rule_file(directory / "AGENTS.md")
        for part in relative_parts:
            directory /= part
            add_rule_file(directory / "AGENTS.md")
    return tuple(sorted(files.values(), key=lambda path: str(path).casefold()))


def root_agent_instruction_files() -> Tuple[Path, ...]:
    path = SCRIPT_DIR / "AGENTS.md"
    if path.is_symlink():
        raise ValueError("项目根目录 AGENTS.md 不允许是符号链接")
    return (path,) if path.is_file() else ()


def render_agent_instruction_bundle(files: Sequence[Path]) -> str:
    instructions: List[Dict[str, str]] = []
    for path in files:
        try:
            content = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError(f"{display_project_path(path)} 必须是 UTF-8 编码") from error
        instructions.append(
            {
                "path": display_project_path(path),
                "content": content,
            }
        )
    if not instructions:
        return "无适用的项目 AGENTS.md。"
    return json.dumps(instructions, ensure_ascii=False, indent=2)


def display_project_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(SCRIPT_DIR.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def authorization_matches_in_file(path: Path) -> Tuple[str, ...]:
    try:
        content = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return (f"{display_project_path(path)}（文件无法读取，按受保护规则处理）",)
    matches: List[str] = []
    lines = content.splitlines()
    for pattern in AUTHORIZATION_RULE_PATTERNS:
        match = pattern.search(content)
        if match is None:
            continue
        line_number = content.count("\n", 0, match.start()) + 1
        line = lines[line_number - 1].strip()
        detail = f"{display_project_path(path)}:{line_number}：{compact_console_text(line, 320)}"
        if detail not in matches:
            matches.append(detail)
    return tuple(matches)


def applicable_authorization_files(plan: PlanSnapshot) -> Tuple[Path, ...]:
    files: Dict[Path, Path] = {}
    if RULES_FILE.is_file():
        files[RULES_FILE.resolve()] = RULES_FILE
    for task in plan.tasks:
        for path in authorization_rule_files(task):
            files[path.resolve()] = path
    return tuple(sorted(files.values(), key=lambda path: str(path).casefold()))


def build_authorization_context(
    task: Optional[PlanTask],
    plan: Optional[PlanSnapshot] = None,
) -> AuthorizationContext:
    active_plan = plan or parse_plan_file()
    all_files = applicable_authorization_files(active_plan)
    files = authorization_rule_files(task) if task is not None else ()
    matches: List[str] = []
    digest = hashlib.sha256()
    for path in (PLAN_FILE, *all_files):
        resolved_path = path.resolve()
        digest.update(display_project_path(resolved_path).encode("utf-8"))
        digest.update(b"\0")
        content_bytes = path.read_bytes()
        digest.update(content_bytes)
        digest.update(b"\0")
    context_files: Dict[Path, Path] = {path.resolve(): path for path in files}
    if RULES_FILE.is_file():
        context_files[RULES_FILE.resolve()] = RULES_FILE
    if task is not None:
        for path in context_files.values():
            for detail in authorization_matches_in_file(path):
                if detail not in matches:
                    matches.append(detail)
    return AuthorizationContext(
        tuple(sorted(context_files.values(), key=lambda path: str(path).casefold())),
        tuple(matches),
        digest.hexdigest(),
    )


def authorization_context_digest(context: AuthorizationContext) -> str:
    return context.digest


def authorization_rule_matches(context: AuthorizationContext) -> Tuple[str, ...]:
    return context.matches


def project_rules_require_authorization(context: AuthorizationContext) -> bool:
    return bool(authorization_rule_matches(context))


def matching_authorization_scope(
    task: TaskState,
    context: AuthorizationContext,
) -> Optional[str]:
    if not AUTHORIZATION_FILE.is_file():
        return None
    try:
        authorization = read_json(AUTHORIZATION_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if type(authorization.get("version")) is not int or authorization.get("version") != 1:
        return None
    if authorization.get("status") != "authorized":
        return None
    if authorization.get("area") != AUTHORIZATION_AREA:
        return None
    if authorization.get("plan_digest") != authorization_context_digest(context):
        return None
    scope = authorization.get("scope")
    if scope == "plan":
        return scope
    if scope == "task" and authorization.get("task_id") == task.task_id:
        return scope
    return None


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def create_authorization_request(
    task: TaskState,
    context: AuthorizationContext,
) -> None:
    request_id = f"REQ-AUTH-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    rule_matches = authorization_rule_matches(context)
    rule_summary = "；".join(rule_matches)
    request = {
        "version": 1,
        "request_id": request_id,
        "kind": "human_action",
        "task_id": task.task_id,
        "reason": f"项目规则要求在修改前取得用户明确授权。授权依据：{rule_summary}",
        "targets": [f"当前任务 {task.task_id}：{task.title}", *rule_matches],
        "risk_level": "medium",
        "risk": "授权只允许当前计划必要范围内的工作区代码修改，不扩大沙箱或系统权限",
        "timeout_seconds": 21600,
        "instructions": "请核对上方授权依据和涉及位置，再选择仅授权当前任务或授权当前计划中必要的修改",
        "authorization": {
            "area": AUTHORIZATION_AREA,
            "plan_digest": authorization_context_digest(context),
            "allowed_scopes": ["task", "plan"],
        },
    }
    atomic_write_json(PENDING_PERMISSION_FILE, request)


def reconcile_pending_authorization_request(
    task: Optional[TaskState],
    context: AuthorizationContext,
) -> None:
    if not PENDING_PERMISSION_FILE.exists():
        return
    if PENDING_PERMISSION_FILE.is_symlink() or not PENDING_PERMISSION_FILE.is_file():
        return
    try:
        request = read_json(PENDING_PERMISSION_FILE)
    except ValueError:
        return
    authorization = request.get("authorization")
    if not isinstance(authorization, dict):
        return
    invalid_reason: Optional[str] = None
    if authorization.get("area") != AUTHORIZATION_AREA:
        invalid_reason = "授权区域标识已变化"
    elif authorization.get("plan_digest") != authorization_context_digest(context):
        invalid_reason = "适用项目规则或 PLAN.md 已变化"
    elif task is None or request.get("task_id") != task.task_id:
        invalid_reason = "待授权任务已不再是当前任务"
    if invalid_reason is None:
        return
    if not isinstance(request.get("request_id"), str) or not isinstance(request.get("task_id"), str):
        raise ValueError("授权请求缺少 request_id 或 task_id，无法安全归档")
    archive_permission(
        request,
        {
            "version": 1,
            "request_id": request["request_id"],
            "task_id": request["task_id"],
            "status": "invalidated",
            "finished_at": now_iso(),
            "note": invalid_reason,
        },
    )
    print_color(f"旧授权请求已失效并归档：{invalid_reason}。", Colors.YELLOW)


def ensure_authorization(
    snapshot: StateSnapshot,
    context: AuthorizationContext,
) -> None:
    task = snapshot.next_task
    reconcile_pending_authorization_request(task, context)
    if task is None or not project_rules_require_authorization(context):
        return
    if matching_authorization_scope(task, context) is not None or PENDING_PERMISSION_FILE.exists():
        return
    create_authorization_request(task, context)


def record_authorization_grant(request: Dict[str, Any], scope: str) -> None:
    authorization = request.get("authorization")
    if not isinstance(authorization, dict):
        raise ValueError("该请求不支持授权范围选择")
    if authorization.get("area") != AUTHORIZATION_AREA:
        raise ValueError("授权区域标识与当前脚本不一致")
    allowed_scopes = authorization.get("allowed_scopes")
    if not isinstance(allowed_scopes, list) or scope not in allowed_scopes:
        raise ValueError(f"该请求不允许 {scope} 授权范围")
    plan = parse_plan_file()
    try:
        plan_task = plan.task(request["task_id"])
    except (KeyError, StopIteration) as error:
        raise RuntimeError("授权请求对应的任务已不在当前 PLAN.md 中") from error
    context = build_authorization_context(plan_task, plan=plan)
    plan_digest = authorization.get("plan_digest")
    if plan_digest != authorization_context_digest(context):
        raise RuntimeError("适用项目规则或 PLAN.md 已变化，本次授权请求已失效，请重新运行监督脚本")
    grant = {
        "version": 1,
        "status": "authorized",
        "area": authorization.get("area"),
        "scope": scope,
        "plan_digest": plan_digest,
        "task_id": request["task_id"] if scope == "task" else None,
        "request_id": request["request_id"],
        "authorized_at": now_iso(),
    }
    atomic_write_json(AUTHORIZATION_FILE, grant)


def worker_authorization_context(
    task: TaskState,
    context: AuthorizationContext,
) -> str:
    if not project_rules_require_authorization(context):
        return "当前任务 allowed_paths 未命中任何受保护范围，无需项目规则授权。"
    scope = matching_authorization_scope(task, context)
    if scope == "plan":
        return (
            "用户已明确授权当前计划内受适用项目规则保护的必要修改。"
            "该授权仅限当前计划和工作区，不包括系统提权、项目外访问、其他高风险操作。"
        )
    if scope == "task":
        return (
            f"用户已明确授权任务 {task.task_id} 中受适用项目规则保护的必要修改。"
            "该授权仅限本任务和工作区，不包括系统提权、项目外访问、其他高风险操作。"
        )
    return "受适用项目规则保护的修改尚未获得授权，如任务需要此类修改，必须先写入 human_action 权限请求。"


def ensure_completion_marker(snapshot: StateSnapshot) -> None:
    if snapshot.next_task is not None or snapshot.has_completion_marker:
        return
    content = STATE_FILE.read_text(encoding="utf-8").rstrip()
    atomic_write_text(STATE_FILE, f"{content}\n\n{ALL_COMPLETED}\n")


def rotate_logs(max_total_bytes: int) -> None:
    log_root = LOG_DIR.resolve()
    files = sorted(
        (path for path in LOG_DIR.glob("*.log") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
    )
    total = sum(path.stat().st_size for path in files)
    for path in files:
        if total <= max_total_bytes:
            break
        resolved = path.resolve()
        if log_root not in resolved.parents:
            raise RuntimeError(f"拒绝删除日志目录外的文件：{resolved}")
        size = path.stat().st_size
        path.unlink(missing_ok=True)
        total -= size


def process_is_alive(process_id: int) -> bool:
    if process_id <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenProcess(
            process_query_limited_information,
            False,
            process_id,
        )
        if not handle:
            return ctypes.get_last_error() == 5
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@contextmanager
def exclusive_file_lock(
    path: Path,
    busy_message: str,
    metadata: Dict[str, Any],
) -> Iterable[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"锁文件不允许是符号链接：{path.name}")
    lock_file = path.open("a+b")
    acquired = False
    try:
        if lock_file.seek(0, os.SEEK_END) == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError(busy_message) from error
        acquired = True
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(json.dumps(metadata, ensure_ascii=False).encode("utf-8"))
        lock_file.flush()
        os.fsync(lock_file.fileno())
        yield
    finally:
        if acquired:
            lock_file.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


@contextmanager
def supervisor_lock() -> Iterable[None]:
    ensure_runtime_directories()
    metadata = {
        "pid": os.getpid(),
        "lock_id": uuid.uuid4().hex,
        "created_at": now_iso(),
    }
    with exclusive_file_lock(
        SUPERVISOR_LOCK_FILE,
        "自动化监督进程已经运行",
        metadata,
    ):
        atomic_write_json(SUPERVISOR_METADATA_FILE, metadata)
        try:
            yield
        finally:
            try:
                active_metadata = read_json(SUPERVISOR_METADATA_FILE)
            except (OSError, ValueError, json.JSONDecodeError):
                active_metadata = None
            if (
                isinstance(active_metadata, dict)
                and active_metadata.get("lock_id") == metadata["lock_id"]
            ):
                SUPERVISOR_METADATA_FILE.unlink(missing_ok=True)


class WindowsProcessJob:
    def __init__(self, handle: int, kernel32: Any, ntdll: Any) -> None:
        self.handle = handle
        self.kernel32 = kernel32
        self.ntdll = ntdll
        self.closed = False

    @classmethod
    def create(cls) -> "WindowsProcessJob":
        if os.name != "nt":
            raise RuntimeError("Windows Job Object 只能在 Windows 上创建")
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("read_operation_count", ctypes.c_uint64),
                ("write_operation_count", ctypes.c_uint64),
                ("other_operation_count", ctypes.c_uint64),
                ("read_transfer_count", ctypes.c_uint64),
                ("write_transfer_count", ctypes.c_uint64),
                ("other_transfer_count", ctypes.c_uint64),
            ]

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("per_process_user_time_limit", ctypes.c_int64),
                ("per_job_user_time_limit", ctypes.c_int64),
                ("limit_flags", wintypes.DWORD),
                ("minimum_working_set_size", ctypes.c_size_t),
                ("maximum_working_set_size", ctypes.c_size_t),
                ("active_process_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority_class", wintypes.DWORD),
                ("scheduling_class", wintypes.DWORD),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("basic_limit_information", BasicLimitInformation),
                ("io_info", IoCounters),
                ("process_memory_limit", ctypes.c_size_t),
                ("job_memory_limit", ctypes.c_size_t),
                ("peak_process_memory_used", ctypes.c_size_t),
                ("peak_job_memory_used", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = ctypes.c_long

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        job = cls(handle, kernel32, ntdll)
        information = ExtendedLimitInformation()
        information.basic_limit_information.limit_flags = 0x00002000
        if not kernel32.SetInformationJobObject(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            job.close()
            raise error
        return job

    def assign_and_resume(self, process: subprocess.Popen[str]) -> None:
        import ctypes
        from ctypes import wintypes

        process_handle = wintypes.HANDLE(int(process._handle))
        if not self.kernel32.AssignProcessToJobObject(self.handle, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        status = self.ntdll.NtResumeProcess(process_handle)
        if status < 0:
            raise OSError(f"NtResumeProcess 失败，NTSTATUS=0x{status & 0xFFFFFFFF:08X}")

    def wait_empty(self, timeout_seconds: float) -> bool:
        import ctypes
        from ctypes import wintypes

        class BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("total_user_time", ctypes.c_int64),
                ("total_kernel_time", ctypes.c_int64),
                ("this_period_total_user_time", ctypes.c_int64),
                ("this_period_total_kernel_time", ctypes.c_int64),
                ("total_page_fault_count", wintypes.DWORD),
                ("total_processes", wintypes.DWORD),
                ("active_processes", wintypes.DWORD),
                ("total_terminated_processes", wintypes.DWORD),
            ]

        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            information = BasicAccountingInformation()
            if not self.kernel32.QueryInformationJobObject(
                self.handle,
                1,
                ctypes.byref(information),
                ctypes.sizeof(information),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if information.active_processes == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def terminate(self) -> None:
        if self.closed:
            return
        import ctypes

        if not self.kernel32.TerminateJobObject(self.handle, 1):
            error_code = ctypes.get_last_error()
            if error_code != 5:
                raise ctypes.WinError(error_code)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.kernel32.CloseHandle(self.handle)


def terminate_process_tree(
    process: subprocess.Popen[str],
    process_job: Optional[WindowsProcessJob] = None,
) -> None:
    if process.poll() is not None:
        if process_job is None:
            return
        try:
            if process_job.wait_empty(0):
                return
        except OSError:
            pass
    if process_job is not None:
        try:
            process_job.terminate()
            process_job.wait_empty(30)
        except OSError:
            pass
    elif os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()


def build_child_environment() -> Dict[str, str]:
    environment = os.environ.copy()
    environment["TEMP"] = str(TEMP_DIR)
    environment["TMP"] = str(TEMP_DIR)
    environment["TMPDIR"] = str(TEMP_DIR)
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def build_worker_environment(task_id: str) -> Dict[str, str]:
    environment = build_child_environment()
    task_temp = TEMP_DIR / (
        f"{task_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    )
    task_temp.mkdir(parents=True)
    environment["TEMP"] = str(task_temp)
    environment["TMP"] = str(task_temp)
    environment["TMPDIR"] = str(task_temp)
    return environment


def stream_reader(stream: Any, output_queue: "queue.Queue[Optional[str]]") -> None:
    try:
        for line in iter(stream.readline, ""):
            output_queue.put(line)
    except (OSError, ValueError):
        pass
    finally:
        output_queue.put(None)
        stream.close()


def normalized_console_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = ANSI_ESCAPE_PATTERN.sub("", value).replace("\r\n", "\n").replace("\r", "\n").strip()
    lines: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if len(stripped) >= 4 and stripped.startswith("**") and stripped.endswith("**"):
            line = stripped[2:-2]
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def compact_console_text(value: Any, limit: int = 220) -> str:
    text = " ".join(normalized_console_text(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def print_console_block(label: str, text: Any, color: str) -> None:
    normalized = normalized_console_text(text)
    if not normalized:
        return
    lines = normalized.splitlines()
    safe_print(f"{color}{label}{Colors.RESET}  {lines[0]}", flush=True)
    for line in lines[1:]:
        safe_print(f"      {line}", flush=True)


def command_failure_tail(output: Any, max_lines: int = 8) -> str:
    normalized = normalized_console_text(output)
    if not normalized:
        return ""
    lines = [line for line in normalized.splitlines() if line.strip()]
    clipped = [compact_console_text(line, 240) for line in lines[-max_lines:]]
    return "\n".join(clipped)


def render_codex_item(item: Dict[str, Any], started: bool) -> None:
    item_type = item.get("type")
    if item_type == "command_execution":
        if started:
            print_console_block("执行：", compact_console_text(item.get("command")), Colors.YELLOW)
            return
        exit_code = item.get("exit_code")
        status = item.get("status")
        if exit_code == 0 or status == "completed" and exit_code is None:
            print_console_block("结果：", "命令执行成功", Colors.GREEN)
            return
        result_text = "命令执行失败"
        if exit_code is not None:
            result_text += f"（退出码 {exit_code}）"
        print_console_block("结果：", result_text, Colors.RED)
        failure_output = command_failure_tail(item.get("aggregated_output"))
        if failure_output:
            print_console_block("错误：", failure_output, Colors.RED)
        return
    if started:
        return
    if item_type == "reasoning":
        print_console_block("思考：", item.get("text"), Colors.DARK_GRAY)
    elif item_type == "agent_message":
        print_console_block("Codex：", item.get("text"), Colors.CYAN)
    elif item_type == "file_change":
        changes = item.get("changes")
        if isinstance(changes, list):
            paths = [compact_console_text(change.get("path")) for change in changes if isinstance(change, dict)]
            detail = f"修改 {len(changes)} 个文件"
            if paths:
                detail += "\n" + "\n".join(path for path in paths if path)
            print_console_block("修改：", detail, Colors.GREEN)
        else:
            print_console_block("修改：", item.get("text") or "文件变更已完成", Colors.GREEN)
    elif item_type in {"error", "command_error"}:
        print_console_block("错误", item.get("message") or item.get("text") or item.get("error"), Colors.RED)


def render_codex_json_line(line: str) -> None:
    stripped = line.strip()
    if not stripped:
        return
    try:
        event = json.loads(stripped)
    except json.JSONDecodeError:
        print_console_block("输出：", stripped, Colors.DARK_GRAY)
        return
    if not isinstance(event, dict):
        return
    event_type = event.get("type")
    item = event.get("item")
    if isinstance(item, dict) and event_type in {"item.started", "item.completed", "item.failed"}:
        render_codex_item(item, event_type == "item.started")
        return
    if event_type in {"reasoning", "agent_message", "command_execution", "file_change", "command_error"}:
        render_codex_item(event, False)
        return
    if event_type in {"error", "turn.failed"}:
        error = event.get("message") or event.get("error") or event.get("details")
        if isinstance(error, dict):
            error = json.dumps(error, ensure_ascii=False)
        print_console_block("错误", error or "Codex 会话发生未知错误", Colors.RED)


def update_retry_summary(summary: RetrySummary, line: str) -> RetrySummary:
    stripped = line.strip()
    if not stripped.startswith("{"):
        return summary
    try:
        event = json.loads(stripped)
    except json.JSONDecodeError:
        return summary
    if not isinstance(event, dict):
        return summary
    event_type = event.get("type")
    item = event.get("item")
    if not isinstance(item, dict):
        item = event
    item_type = item.get("type")
    changed_paths = list(summary.changed_paths)
    last_failed_command = summary.last_failed_command
    core_error = summary.core_error
    final_message = summary.final_message
    if item_type == "file_change":
        changes = item.get("changes")
        if isinstance(changes, list):
            for change in changes:
                if not isinstance(change, dict):
                    continue
                path = change.get("path")
                if isinstance(path, str) and path and path not in changed_paths:
                    changed_paths.append(path)
    elif item_type == "command_execution" and event_type in {"item.completed", "item.failed"}:
        exit_code = item.get("exit_code")
        status = item.get("status")
        if exit_code not in {None, 0} or status in {"failed", "declined"}:
            last_failed_command = compact_console_text(item.get("command"), 600)
            core_error = command_failure_tail(item.get("aggregated_output"), 8)
    elif item_type == "agent_message" and event_type == "item.completed":
        final_message = compact_console_text(item.get("text"), 1000)
    elif event_type in {"error", "turn.failed"}:
        error = event.get("message") or event.get("error") or event.get("details")
        if isinstance(error, dict):
            error = json.dumps(error, ensure_ascii=False)
        core_error = compact_console_text(error, 1200)
    return RetrySummary(tuple(changed_paths), last_failed_command, core_error, final_message)


def run_process(
    command: Sequence[str],
    cwd: Path,
    environment: Dict[str, str],
    quiet_timeout_seconds: int,
    absolute_timeout_seconds: int,
    log_prefix: str,
    render_codex_events: bool = False,
    stdin_text: Optional[str] = None,
) -> ProcessResult:
    ensure_runtime_directories()
    rotate_logs(100 * 1024 * 1024)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = LOG_DIR / f"{timestamp}-{log_prefix}-{uuid.uuid4().hex[:8]}.log"
    creation_flags = 0
    process_job: Optional[WindowsProcessJob] = None
    if os.name == "nt":
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | WINDOWS_CREATE_SUSPENDED
    started_at = time.monotonic()
    last_activity_at = started_at
    timeout_reason: Optional[str] = None
    output_queue: "queue.Queue[Optional[str]]" = queue.Queue()
    output_tail: List[str] = []
    retry_summary = RetrySummary()
    console_output_enabled = True
    stdin_stream = None
    if stdin_text is not None:
        stdin_stream = tempfile.TemporaryFile(
            mode="w+",
            encoding="utf-8",
            dir=TEMP_DIR,
        )
        stdin_stream.write(stdin_text)
        stdin_stream.seek(0)
    with log_file.open("w", encoding="utf-8", buffering=1) as log:
        log.write(f"started_at={now_iso()}\n")
        log.write(f"cwd={cwd}\n")
        log.write(f"command={json.dumps(list(command), ensure_ascii=False)}\n")
        try:
            if stdin_text is not None:
                log.write(f"stdin={json.dumps(stdin_text, ensure_ascii=False)}\n")
            try:
                if os.name == "nt":
                    process_job = WindowsProcessJob.create()
                process = subprocess.Popen(
                    list(command),
                    cwd=cwd,
                    env=environment,
                    stdin=stdin_stream if stdin_stream is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=creation_flags,
                    start_new_session=os.name != "nt",
                )
                if process_job is not None:
                    try:
                        process_job.assign_and_resume(process)
                    except BaseException:
                        terminate_process_tree(process, process_job)
                        raise
            except OSError as error:
                if process_job is not None:
                    process_job.close()
                raise ProcessStartError(error) from error
            except BaseException:
                if process_job is not None:
                    process_job.close()
                raise
            assert process.stdout is not None
            reader = threading.Thread(target=stream_reader, args=(process.stdout, output_queue), daemon=True)
            reader.start()
            stream_finished = False
            reader_abandoned = False
            process_exited_at: Optional[float] = None
            try:
                while True:
                    try:
                        line = output_queue.get(timeout=1)
                        if line is None:
                            stream_finished = True
                        else:
                            last_activity_at = time.monotonic()
                            log.write(line)
                            retry_summary = update_retry_summary(retry_summary, line)
                            output_tail.append(line.rstrip()[-MAX_RAW_EVENT_TAIL_CHARS:])
                            del output_tail[:-PROCESS_OUTPUT_TAIL_LINES]
                            if console_output_enabled:
                                try:
                                    if render_codex_events:
                                        render_codex_json_line(line)
                                    else:
                                        safe_print(line, end="", flush=True)
                                    error = _console_output_error
                                    if error is not None:
                                        raise error
                                except OSError as error:
                                    console_output_enabled = False
                                    log.write(
                                        "\nconsole_output_disabled="
                                        f"{type(error).__name__}: {error}\n"
                                    )
                    except queue.Empty:
                        pass
                    current_time = time.monotonic()
                    if process.poll() is None:
                        process_exited_at = None
                        if current_time - started_at >= absolute_timeout_seconds:
                            timeout_reason = f"超过绝对时限 {absolute_timeout_seconds} 秒"
                            terminate_process_tree(process, process_job)
                        elif current_time - last_activity_at >= quiet_timeout_seconds:
                            timeout_reason = f"连续 {quiet_timeout_seconds} 秒没有输出"
                            terminate_process_tree(process, process_job)
                    else:
                        if process_exited_at is None:
                            process_exited_at = current_time
                        if stream_finished and output_queue.empty():
                            break
                        if current_time - process_exited_at >= PROCESS_OUTPUT_DRAIN_SECONDS:
                            log.write(
                                f"\noutput_drain_timeout={PROCESS_OUTPUT_DRAIN_SECONDS}\n"
                            )
                            reader_abandoned = True
                            break
            except BaseException:
                terminate_process_tree(process, process_job)
                raise
            if not reader_abandoned:
                reader.join(timeout=5)
            return_code = process.returncode
            if return_code is None:
                raise RuntimeError("进程输出结束后仍未取得退出码")
            if process_job is not None:
                try:
                    process_tree_empty = process_job.wait_empty(PROCESS_TREE_DRAIN_SECONDS)
                except OSError as error:
                    process_tree_empty = False
                    log.write(
                        "\nprocess_tree_query_error="
                        f"{type(error).__name__}: {error}\n"
                    )
                if not process_tree_empty:
                    log.write(f"\nprocess_tree_drain_timeout={PROCESS_TREE_DRAIN_SECONDS}\n")
                    terminate_process_tree(process, process_job)
                    log.write("process_tree_cleanup=terminated_remaining_job_processes\n")
            duration = time.monotonic() - started_at
            log.write(f"\nfinished_at={now_iso()}\n")
            log.write(f"return_code={return_code}\n")
            log.write(f"duration_seconds={duration:.1f}\n")
            if timeout_reason:
                log.write(f"timeout_reason={timeout_reason}\n")
        finally:
            if process_job is not None:
                process_job.close()
            if stdin_stream is not None:
                stdin_stream.close()
    return ProcessResult(
        return_code,
        timeout_reason is not None,
        timeout_reason,
        duration,
        log_file,
        "\n".join(output_tail),
        retry_summary,
    )


def resolve_codex_executable() -> str:
    executable = shutil.which("codex")
    if not executable:
        raise FileNotFoundError("找不到 codex 命令，请先安装 Codex CLI 并加入 PATH")
    return executable


def verify_codex_executable(codex_executable: str) -> str:
    try:
        result = subprocess.run(
            [codex_executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"Codex CLI 本地自检失败：{error}") from error
    output = normalized_console_text(result.stdout)
    if result.returncode != 0:
        detail = f"：{compact_console_text(output)}" if output else ""
        raise RuntimeError(f"Codex CLI 本地自检退出码 {result.returncode}{detail}")
    return output or "版本未知"


def create_session_workspace(environment: Dict[str, str], label: str) -> Path:
    temporary_root = Path(environment["TEMP"])
    session_workspace = temporary_root / f"codex-workspace-{label}-{uuid.uuid4().hex[:8]}"
    session_workspace.mkdir(parents=True)
    return session_workspace


def build_codex_command(
    codex_executable: str,
    model: str,
    effort: str,
    session_workspace: Path,
    writable_roots: Sequence[Path],
) -> List[str]:
    command = [
        codex_executable,
        "--ask-for-approval",
        "never",
        "--sandbox",
        "workspace-write",
        "--model",
        model,
        "--config",
        f'model_reasoning_effort="{effort}"',
        "--cd",
        str(session_workspace),
    ]
    for writable_root in writable_roots:
        command.extend(["--add-dir", str(writable_root)])
    command.extend([
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--json",
        "--color",
        "never",
        "-",
    ])
    return command


def deterministic_codex_startup_error(result: ProcessResult) -> Optional[str]:
    output = normalized_console_text(result.output_tail)
    normalized_output = output.casefold()
    if result.return_code not in {126, 127} and "stdin is not a terminal" not in normalized_output:
        return None
    detail = command_failure_tail(output)
    reason = f"Codex CLI 启动失败（退出码 {result.return_code}）"
    if detail:
        reason = f"{reason}：{detail}"
    return reason


def architect_prompt(requirements: str) -> str:
    agent_instructions = render_agent_instruction_bundle(root_agent_instruction_files())
    return f"""你是当前项目的高级系统架构师，你现在只负责生成可供自动化代理执行的规划文档，不实现业务代码。

实际项目根目录是 `{SCRIPT_DIR}`。当前会话工作目录是隔离目录，读取、检索和命令执行必须显式以实际项目根目录为目标，所有计划路径仍相对实际项目根目录书写。只有 `{AUTOMATION_DIR}` 被授予写权限。

项目需求如下：

<PROJECT_REQUIREMENTS>
{requirements.strip()}
</PROJECT_REQUIREMENTS>

监督器显式提供的项目级 AGENTS.md 如下；无论当前目录是否属于 Git 项目，都必须遵守：

<APPLICABLE_AGENTS_JSON>
{agent_instructions}
</APPLICABLE_AGENTS_JSON>

{ONE_PASS_TASK_STANDARD}

请严格执行：

1. 根级 AGENTS.md 已由监督器显式提供，检查更深子目录时，仍需读取该目录内新增且适用的 AGENTS.md；
2. 本阶段只允许在 .codex-automation/planning 目录中创建 RULES.md 和 PLAN.md。STATE.md 由监督脚本根据 PLAN.md 自动生成。{SUPERVISOR_BLACK_BOX_RULE} 禁止编写业务代码、构建、安装、部署、访问项目外文件、请求提升权限；
3. .codex-automation/planning/RULES.md 必须描述项目目标、非目标、技术栈、目录与模块职责、代码、命名规范、测试与构建规则、安全边界、日志配置、架构假设、完成定义；
4. 规划阶段完成必要的代码定位和 API/模式选择，把结论写入 preconditions、implementation 、 decision_constraints。worker 不得承担调查、分类或设计任务；
5. 按一次做对任务标准决定边界。测试用例、单个枚举值、单个映射分支、单个日志点只有在共享同一实现边界时才写进同一验收矩阵，不得机械拆分或机械合并；
6. 每个任务完成后必须形成可独立验证、可独立保留的有意义代码状态，并能由一次独立 Codex 会话完成；
7. PLAN.md 必须包含且只能包含一个由 `{PLAN_DATA_START}` 和 `{PLAN_DATA_END}` 包围的 JSON 数据块。数据块格式如下：

{PLAN_DATA_START}
{{
  "version": {PLAN_FORMAT_VERSION},
  "tasks": [
    {{
      "id": "T001",
      "title": "简洁任务标题",
      "deliverable": "独立交付物",
      "cohesion_key": "稳定且全计划唯一的内聚键",
      "depends_on": [],
      "workspace_root": "容纳全部 allowed_paths 的最小现有项目相对目录",
      "allowed_paths": ["完成当前交付物所需的精确文件；验证型任务可以为空数组"],
      "generated_paths": ["验证命令会写入的精确目录树，统一使用 path/**；没有则为空数组"],
      "preconditions": ["开始前核对的具体文件、符号、代码状态"],
      "implementation": ["按唯一顺序执行的具体文件、符号、API、行为修改"],
      "decision_constraints": [
        "必须：使用的具体 API、组件、现有模式",
        "禁止：本任务不能采用的具体替代方案",
        "冲突时：出现何种具体代码现实时停止并请求 human_action"
      ],
      "non_goals": ["本任务明确不做的内容"],
      "acceptance": ["客观验收条件，相关分支组成矩阵"],
      "validation": ["具体命令或静态核验"],
      "risk": "风险及控制方式",
      "split_reason": "仅在与相邻任务范围和验证高度相同时填写"
    }}
  ]
}}
{PLAN_DATA_END}

8. 依赖只能指向更早的任务，cohesion_key 不得重复；workspace_root 必须是容纳全部 allowed_paths 的最小现有普通目录，除非交付物确实跨顶层边界，否则禁止写成项目根；allowed_paths 只允许精确文件且可以仅在纯验证任务中为空；generated_paths 只允许显式 path/** 且可以为空；decision_constraints 必须完整包含“必须：”“禁止：”“冲突时：”三类具体约束；
9. 不得编造账号、密钥、服务地址、用户未提供的关键业务规则。存在非关键缺口时使用最小假设并记录在 RULES.md；存在会改变架构方向的关键歧义时，在 RULES.md 和 PLAN.md 中明确记录阻塞，不开始实现；
10. 写入前逐项执行一次“worker 是否仍需自行选择文件、API、架构或验收方式”的审查，答案为是时继续规划或拆分，不得把模糊任务写入 PLAN.md；
11. 完成后只报告 RULES.md、PLAN.md 是否生成成功、任务总数、是否全部通过一次做对审查。
"""


def planning_review_prompt() -> str:
    agent_instructions = render_agent_instruction_bundle(root_agent_instruction_files())
    return f"""你是自动化计划质量审查者，只允许修改 .codex-automation/planning/RULES.md 和 PLAN.md，不实现业务代码，不创建 STATE.md。{SUPERVISOR_BLACK_BOX_RULE}

实际项目根目录是 `{SCRIPT_DIR}`。当前会话工作目录是隔离目录，读取、检索和命令执行必须显式以实际项目根目录为目标，计划路径仍相对实际项目根目录书写。只有 `{AUTOMATION_DIR}` 被授予写权限。

监督器显式提供的项目级 AGENTS.md 如下，无论当前目录是否属于 Git 项目，都必须遵守：

<APPLICABLE_AGENTS_JSON>
{agent_instructions}
</APPLICABLE_AGENTS_JSON>

完整读取这两个文件并检查 PLAN.md 的 `{PLAN_DATA_START}` 机器数据块。必须直接修正后再结束：

{ONE_PASS_TASK_STANDARD}

1. 逐项检查 preconditions 是否能从代码直接核对；workspace_root 是否是容纳全部 allowed_paths 的最小现有目录；allowed_paths 是否只含实际目标文件；generated_paths 是否只含 validation 会写入的显式 path/**；implementation 是否给出关键符号、唯一实现路径和顺序；
2. 逐项检查 decision_constraints 是否明确必须复用的具体 API/组件、禁止的具体替代方案、必须暂停的具体冲突，不接受泛化句子；
3. 规划阶段自行完成调查、定位、盘点、分类、方案选择、架构设计，PLAN 中不得保留此类任务或让后续任务依赖未写明的调查结果；
4. acceptance 必须覆盖与交付物相关的成功、失败、空态、生命周期、恢复矩阵，不适用的维度无需虚构，validation 必须是具体命令或有边界且有预期结果的静态核验；
5. 仅按一次做对标准拆分或合并，禁止根据期望数量、比例、旧任务数量、token 数目标调整粒度；
6. 保持 JSON 为 version={PLAN_FORMAT_VERSION}，任务 ID 稳定且依赖只指向更早任务，cohesion_key 全局唯一；
7. 不得仅报告问题。完成修正后只报告最终任务数量和是否所有任务通过一次做对审查。
"""


def retry_prompt_context(
    result: Optional[ProcessResult],
    consecutive_no_progress: int,
    permission_result: Optional[Dict[str, Any]] = None,
) -> str:
    if result is None and permission_result is None:
        return "无"
    value: Dict[str, Any] = {"consecutive_no_progress": consecutive_no_progress}
    if result is not None:
        summary = result.retry_summary
        changed_paths = [
            path
            for path in summary.changed_paths
            if Path(path).resolve() != PENDING_PERMISSION_FILE.resolve()
        ]
        value.update(
            {
                "previous_return_code": result.return_code,
                "timed_out": result.timed_out,
                "timeout_reason": result.timeout_reason,
                "changed_paths": changed_paths,
                "last_failed_command": summary.last_failed_command,
                "core_error": summary.core_error,
                "previous_final_message": summary.final_message,
            }
        )
    if permission_result is not None:
        value["permission_result"] = permission_result
        value["permission_result_state"] = {
            "archived": True,
            "pending_request_exists": False,
            "request_id_reusable": False,
            "required_action_after_fix": (
                "使用本会话监督器预分配的新 request_id 创建新的权限请求；"
                "不得把该归档结果视为仍存在的 PERMISSION_REQUEST.json"
            ),
        }
    return json.dumps(value, ensure_ascii=False, indent=2)


def new_worker_permission_request_id(task_id: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"REQ-WORKER-{task_id}-{timestamp}-{uuid.uuid4().hex[:8]}"


def worker_prompt(
    plan_task: PlanTask,
    authorization_context: str,
    completed_count: int,
    total_tasks: int,
    plan_digest: str,
    previous_result: Optional[ProcessResult] = None,
    consecutive_no_progress: int = 0,
    permission_result: Optional[Dict[str, Any]] = None,
    agent_instruction_files: Optional[Sequence[Path]] = None,
) -> str:
    rules = read_rules_file()
    rule_files = (
        authorization_rule_files(plan_task)
        if agent_instruction_files is None
        else tuple(agent_instruction_files)
    )
    agent_instructions = render_agent_instruction_bundle(rule_files)
    task_value = json.dumps(plan_task.prompt_value(), ensure_ascii=False, indent=2)
    generated_patterns = plan_task.generated_paths
    generated_validation_context = (
        "、".join(generated_patterns) if generated_patterns else "无"
    )
    retry_context = retry_prompt_context(
        previous_result,
        consecutive_no_progress,
        permission_result,
    )
    permission_request_id = new_worker_permission_request_id(plan_task.task_id)
    return f"""这是用户明确要求实施的自动化任务。固定执行协议如下：

实际项目根目录是 `{SCRIPT_DIR}`。当前会话工作目录是隔离目录，所有读取、检索、文件修改和命令执行都必须显式以实际项目根目录为目标，任务中的相对路径均相对该项目根目录。

1. 当前任务适用的现有 AGENTS.md 已由监督器显式提供，不得重复读取这些文件，也不得从项目根递归搜索 AGENTS.md。编辑过程中若在目标文件同目录发现未列出的更深层 AGENTS.md，才读取并遵守；
2. 只完成当前任务的完整交付物和验收矩阵，不提前处理后续任务，不做范围外重构，保留用户未提交改动，不得自行选择任务未指定的文件、API、数据模型、架构、验收方式；
3. 开始前逐项核对 preconditions，并严格执行 decision_constraints。若具体代码现实命中“冲突时”条件或导致指定路径不再唯一，必须请求 human_action，不得自行补设计。固定文档路径和任务上下文已由监督器提供，不得重新扫描 PLAN.md、STATE.md、RUN_STATE.json；
4. 禁止读取 .codex-automation/logs、permissions、tmp 和当前活动日志。重试信息只使用监督器提供的结构化摘要；
5. 检索先用 rg -l 定位候选文件，再在少量候选文件内使用有限上下文。禁止 rg -uu、--no-ignore、空正则和无边界全仓输出。单次预期输出不得超过约 20 KiB；
6. 监督器只提供当前任务独立的 TEMP、TMP 和 TMPDIR。不得覆盖监督器提供的环境变量、搜索历史缓存或删除任务外缓存；构建工具、依赖缓存、验证环境完全遵循当前项目规则；
7. 完整命令输出保存在运行日志。成功时只需要退出状态和摘要，失败时只返回失败命令、核心错误、错误附近上下文、末尾，不得超过 120 行；
8. {SUPERVISOR_BLACK_BOX_RULE} 只能编辑 .codex-automation/worker-control/STATE.md 的当前任务复选框和同目录 PERMISSION_REQUEST.json，不得编辑 .codex-automation 的其他内容；
9. 只有实现完成、全部 acceptance 满足且必要 validation 通过后，才能把 STATE.md 中当前任务从 [ ] 改为 [x]；禁止写入 [ALL_COMPLETED]；
10. 最终报告固定为四项：任务状态、修改文件、验证结果、剩余阻塞。不得复述规则和计划。

Windows 沙箱稳定性约束：以下生成目录不会直接授予 worker 写权限：{generated_validation_context}。只读检索和源码修改必须先完成；需要执行会写入这些目录的 validation 命令时，不要先在 worker 沙箱内试跑，直接按 command 权限协议提交该条精确命令，由监督器在用户一次性批准后执行。静态只读 validation 可直接运行。

适用的本轮规则如下：

<RULES>
{rules}
</RULES>

当前任务适用的 AGENTS.md 如下；无论当前目录是否属于 Git 项目，都必须遵守：

<APPLICABLE_AGENTS_JSON>
{agent_instructions}
</APPLICABLE_AGENTS_JSON>

权限协议：仅在沙箱、ACL、管理员/UAC、凭据、高成本 API、项目规则授权、架构决策确实阻塞时使用。当前 worker 启动时不存在待处理的 PERMISSION_REQUEST.json；RETRY_CONTEXT 中的 permission_result 是已归档的历史执行结果，不代表请求文件仍存在，其 request_id 永久不可复用。先尝试一次工作区内安全替代；仍阻塞且不存在 PERMISSION_REQUEST.json 时写入。本会话创建任何一种权限请求都必须使用监督器预分配的唯一 request_id `{permission_request_id}`，不得自行生成或复用其他 request_id。PERMISSION_REQUEST.json 必须只包含一个原始 JSON 对象，首个非空白字符必须是 `{{`，末个非空白字符必须是 `}}`；禁止写入 Markdown 代码围栏、补丁头或 diff 的 `+`/`-` 行前缀，写入后必须执行只读 JSON 解析校验，确认成功后才能结束会话：
command 请求必须额外包含 `command` 字符串数组和 `cwd`；command[0] 必须是可直接启动的程序，不能填写任何 shell 内建命令。确需 shell 语法时，必须显式使用当前平台可用的 shell 可执行程序及其非交互参数。
当前 allowed_paths 内源码被 Windows 沙箱 ACL、`Failed to write file` 或 `setup refresh had errors` 阻塞时，必须使用 sandbox_recovery；不得要求用户手工修改 ACL。监督器会在用户确认后持久备份并原子重建当前任务最小写入根内由 CodexSandbox 账户拥有的最外层目录及普通文件，使所有者回到脚本用户；目录树清单或文件哈希不一致时自动回滚，再用隔离工作目录和 allowed_paths 最小写入根重试。
sandbox_recovery 最小完整格式：{{"version":1,"request_id":"{permission_request_id}","kind":"sandbox_recovery","task_id":"{plan_task.task_id}","reason":"实际沙箱写入错误","targets":["当前 allowed_paths 内被拒绝的精确文件"],"risk_level":"medium","risk":"监督器会持久备份并原子重建当前任务最小写入根内由 CodexSandbox 账户拥有的最外层目录及普通文件，使所有者回到脚本用户；目录树清单或文件哈希不一致时自动回滚","timeout_seconds":1800,"workspace_root":"{plan_task.workspace_root}","plan_digest":"{plan_digest}"}}
human_action 请求必须额外包含 `instructions`，它可以是非空字符串或非空字符串数组，用于告诉用户要确认或完成的具体动作，不能省略该字段。不得重复尝试、不得绕过审批、不得覆盖已有请求。需要 UAC、系统设置、凭据、高成本 API 或无法由监督器执行的真实人工操作时只能使用 human_action。
human_action 最小完整格式：{{"version":1,"request_id":"{permission_request_id}","kind":"human_action","task_id":"<CURRENT_TASK_ID>","reason":"权限来源和实际阻塞","targets":["具体目标"],"risk_level":"low|medium|high","risk":"确认后的实际影响","timeout_seconds":1800,"instructions":"请用户确认或完成的具体动作"}}
若唯一实现确实需要修改当前 allowed_paths 之外的现有普通文件，或为当前交付物新增精确的拆分文件，必须使用 scope_extension，不得要求用户手工编辑 PLAN.md；requested_paths 只能列精确项目相对文件，禁止目录和通配符。用户同意后，监督器会加入这些文件，并在必要时把 workspace_root 自动扩大到能够容纳原范围与新增文件的最小共同目录。
scope_extension 最小完整格式：{{"version":1,"request_id":"{permission_request_id}","kind":"scope_extension","task_id":"{plan_task.task_id}","reason":"该文件为何是当前交付物不可分割的消费方","targets":["待加入文件及相关符号"],"risk_level":"medium","risk":"同意后监督器会加入所列精确文件，并在必要时把 workspace_root 扩大到最小共同目录","timeout_seconds":1800,"requested_paths":["path/to/file.kt"],"plan_digest":"{plan_digest}"}}

当前任务进度：{completed_count}/{total_tasks}

<CURRENT_TASK>
{task_value}
</CURRENT_TASK>

授权状态：{authorization_context}

<RETRY_CONTEXT>
{retry_context}
</RETRY_CONTEXT>

若 RETRY_CONTEXT 不是“无”，直接从已有修改和失败点续做，不得从头重新调查。若代码现实与任务存在会改变架构方向的冲突，写入 human_action 请求后结束，否则持续执行到完成、有效权限请求或真实不可恢复错误。
"""


def load_requirements() -> str:
    requirements = PROJECT_REQUIREMENTS.strip()
    if requirements:
        print_color(f"已读取 {SCRIPT_NAME} 内嵌的初始需求", Colors.DARK_GRAY)
        return requirements
    if sys.stdin.isatty():
        print_color("脚本未内嵌项目需求，请直接粘贴。", Colors.CYAN)
        print_color("项目需求可以多行输入，粘贴完成后必须另起一行只输入 [END] 并按回车。", Colors.YELLOW)
        lines: List[str] = []
        while True:
            try:
                line = read_terminal_input()
            except EOFError:
                break
            if line.strip() == "[END]":
                break
            lines.append(line)
        content = "\n".join(lines).strip()
        if content:
            return content
    else:
        content = sys.stdin.read().strip()
        if content:
            return content
    raise ValueError(
        f"首次运行需要项目需求：请填写 {SCRIPT_NAME} 顶部的 PROJECT_REQUIREMENTS，"
        "或在终端粘贴后另起一行只写下 [END] "
    )


def run_planning_review(
    arguments: argparse.Namespace,
    codex_executable: str,
) -> None:
    environment = build_child_environment()
    session_workspace = create_session_workspace(environment, "plan-review")
    command = build_codex_command(
        codex_executable,
        arguments.model,
        arguments.effort,
        session_workspace,
        (PLANNING_DIR,),
    )
    protected_before = {
        path: capture_optional_file_content(path)
        for path in (
            STATE_FILE,
            RUN_STATE_FILE,
            PENDING_PERMISSION_FILE,
            AUTHORIZATION_FILE,
            SUPERVISOR_METADATA_FILE,
            APPROVAL_CLAIM_FILE,
        )
    }
    changed: Tuple[Path, ...] = ()
    try:
        result = run_process(
            command,
            SCRIPT_DIR,
            environment,
            QUIET_TIMEOUT_SECONDS,
            ABSOLUTE_TIMEOUT_SECONDS,
            "plan-review",
            render_codex_events=True,
            stdin_text=planning_review_prompt(),
        )
    finally:
        try:
            changed = restore_changed_optional_files(protected_before)
        finally:
            remove_owned_temp_path(session_workspace, TEMP_DIR)
    if changed:
        names = ", ".join(path.name for path in changed)
        raise RuntimeError(f"计划审查会话修改了受保护控制文件，已恢复：{names}")
    if result.return_code != 0:
        raise RuntimeError(f"计划质量审查失败，退出码 {result.return_code}，日志：{result.log_file}")


def ensure_planning_documents(arguments: argparse.Namespace, codex_executable: str) -> StateSnapshot:
    existing = [path for path in (RULES_FILE, PLAN_FILE, STATE_FILE) if path.exists()]
    if len(existing) == 3:
        return validate_planning_documents()
    if RULES_FILE.exists() and PLAN_FILE.exists() and not STATE_FILE.exists():
        run_planning_review(arguments, codex_executable)
        plan = parse_plan_file()
        render_state_file(plan)
        return validate_planning_documents()
    if existing:
        names = ", ".join(path.name for path in existing)
        raise RuntimeError(f"规划文件（{names}）已存在，为避免覆盖停止自动生成")
    requirements = load_requirements()
    update_run_state(status="PLANNING", current_task=None)
    print_color("规划文件不存在，正在启动架构师会话……", Colors.YELLOW)
    prompt = architect_prompt(requirements)
    environment = build_child_environment()
    session_workspace = create_session_workspace(environment, "architect")
    command = build_codex_command(
        codex_executable,
        arguments.model,
        arguments.effort,
        session_workspace,
        (PLANNING_DIR,),
    )
    protected_before = {
        path: capture_optional_file_content(path)
        for path in (
            STATE_FILE,
            RUN_STATE_FILE,
            PENDING_PERMISSION_FILE,
            AUTHORIZATION_FILE,
            SUPERVISOR_METADATA_FILE,
            APPROVAL_CLAIM_FILE,
        )
    }
    changed: Tuple[Path, ...] = ()
    try:
        result = run_process(
            command,
            SCRIPT_DIR,
            environment,
            QUIET_TIMEOUT_SECONDS,
            ABSOLUTE_TIMEOUT_SECONDS,
            "architect",
            render_codex_events=True,
            stdin_text=prompt,
        )
    finally:
        try:
            changed = restore_changed_optional_files(protected_before)
        finally:
            remove_owned_temp_path(session_workspace, TEMP_DIR)
    if changed:
        names = ", ".join(path.name for path in changed)
        raise RuntimeError(f"架构师会话修改了受保护控制文件，已恢复：{names}")
    if result.return_code != 0:
        raise RuntimeError(f"架构师会话失败，退出码 {result.return_code}，日志：{result.log_file}")
    run_planning_review(arguments, codex_executable)
    plan = parse_plan_file()
    render_state_file(plan)
    return validate_planning_documents()


def resolve_permission_cwd(request: Dict[str, Any]) -> Path:
    cwd = Path(request["cwd"])
    if not cwd.is_absolute():
        cwd = (SCRIPT_DIR / cwd).resolve()
    else:
        cwd = cwd.resolve()
    if not cwd.is_dir():
        raise ValueError(f"权限请求 cwd 不存在或不是目录：{cwd}")
    return cwd


def resolve_permission_executable(
    command: Sequence[str],
    cwd: Path,
    environment: Optional[Dict[str, str]] = None,
) -> str:
    executable = command[0]
    executable_path = Path(executable)
    has_path = (
        executable_path.is_absolute()
        or "/" in executable
        or "\\" in executable
        or executable_path.parent != Path(".")
    )
    if has_path:
        candidate = executable_path if executable_path.is_absolute() else cwd / executable_path
        candidate = candidate.resolve()
        if candidate.is_file():
            return str(candidate)
    else:
        path_value = None if environment is None else environment.get("PATH")
        resolved = shutil.which(executable, path=path_value)
        if resolved:
            return resolved
    raise PermissionExecutableError(
        executable,
        cwd,
        f"command[0] 不是可直接执行程序：{executable}。shell 内建命令必须显式通过对应 shell 可执行程序调用。",
    )


def permission_instructions_text(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item.strip() for item in value)
    ):
        return "\n".join(f"{index}. {item.strip()}" for index, item in enumerate(value, start=1))
    raise ValueError("human_action 权限请求必须提供非空字符串或非空字符串数组 instructions")


def permission_archive_path(request_id: str) -> Path:
    return PERMISSION_ARCHIVE_DIR / f"{request_id}.json"


def permission_request_fingerprint_payload(request: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "kind": request["kind"],
        "risk_level": request["risk_level"],
    }
    if request["kind"] == "command":
        payload.update(
            {
                "command": list(request["command"]),
                "cwd": str(resolve_permission_cwd(request)),
            }
        )
    elif request["kind"] == "scope_extension":
        payload["requested_paths"] = list(request["requested_paths"])
    elif request["kind"] == SANDBOX_RECOVERY_KIND:
        payload.update(
            {
                "targets": list(request["targets"]),
                "workspace_root": request["workspace_root"],
            }
        )
    else:
        payload.update(
            {
                "targets": list(request["targets"]),
                "instructions": permission_instructions_text(request["instructions"]),
                "authorization": request.get("authorization"),
            }
        )
    return payload


def permission_request_fingerprint(request: Dict[str, Any]) -> str:
    payload = permission_request_fingerprint_payload(request)
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def permission_request_digest(request: Dict[str, Any]) -> str:
    serialized = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def read_plan_permission_grants(plan_digest: str) -> List[Dict[str, Any]]:
    if not PERMISSION_GRANTS_FILE.is_file():
        return []
    value = read_json(PERMISSION_GRANTS_FILE)
    if value.get("version") != 1:
        raise ValueError("计划权限指纹文件 version 必须为 1")
    if value.get("plan_digest") != plan_digest:
        return []
    grants = value.get("grants")
    if not isinstance(grants, list):
        raise ValueError("计划权限指纹文件 grants 必须是数组")
    for grant in grants:
        if not isinstance(grant, dict):
            raise ValueError("计划权限指纹条目必须是对象")
        if not re.fullmatch(r"[0-9a-f]{64}", str(grant.get("fingerprint", ""))):
            raise ValueError("计划权限指纹格式无效")
        request_id = grant.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
            raise ValueError("计划权限指纹来源请求 ID 无效")
    return grants


def permission_request_has_plan_grant(request: Dict[str, Any]) -> bool:
    if request.get("kind") != "command":
        return False
    plan_digest = parse_plan_file().digest
    fingerprint = permission_request_fingerprint(request)
    return any(
        grant["fingerprint"] == fingerprint
        and permission_archive_path(grant["request_id"]).is_file()
        for grant in read_plan_permission_grants(plan_digest)
    )


def record_plan_permission_grant(request: Dict[str, Any]) -> str:
    plan_digest = parse_plan_file().digest
    grants = read_plan_permission_grants(plan_digest)
    fingerprint = permission_request_fingerprint(request)
    if not any(grant["fingerprint"] == fingerprint for grant in grants):
        grants.append(
            {
                "fingerprint": fingerprint,
                "kind": request["kind"],
                "request_id": request["request_id"],
                "authorized_at": now_iso(),
            }
        )
    atomic_write_json(
        PERMISSION_GRANTS_FILE,
        {
            "version": 1,
            "plan_digest": plan_digest,
            "grants": grants,
        },
    )
    return fingerprint


def rebind_plan_permission_grants(previous_plan_digest: str, current_plan_digest: str) -> None:
    if not PERMISSION_GRANTS_FILE.is_file():
        return
    grants = read_plan_permission_grants(previous_plan_digest)
    atomic_write_json(
        PERMISSION_GRANTS_FILE,
        {
            "version": 1,
            "plan_digest": current_plan_digest,
            "grants": grants,
        },
    )


def permission_request_id_is_archived(request_id: str) -> bool:
    return permission_archive_path(request_id).exists()


def permission_result_summary(
    request: Dict[str, Any],
    result: Dict[str, Any],
    archive_path: Path,
) -> Dict[str, Any]:
    summary = {
        "request_id": request["request_id"],
        "task_id": request["task_id"],
        "kind": request.get("kind", "invalid"),
        "status": result["status"],
        "result_file": str(archive_path.relative_to(SCRIPT_DIR)),
    }
    for field_name in (
        "return_code",
        "timed_out",
        "timeout_reason",
        "failure_kind",
        "note",
        "added_paths",
        "workspace_root",
        "repaired_roots",
        "acl_backup",
        "cleaned_metadata",
        "normalized_owners",
        "ownership_backup",
        "log_file",
        "failure_summary",
        "authorization_scope",
        "permission_fingerprint",
        "auto_approved",
    ):
        if field_name in result:
            summary[field_name] = result[field_name]
    return summary


def recover_archived_permission() -> Optional[Dict[str, Any]]:
    pending_request: Optional[Dict[str, Any]] = None
    if PENDING_PERMISSION_FILE.exists():
        if PENDING_PERMISSION_FILE.is_symlink() or not PENDING_PERMISSION_FILE.is_file():
            return None
        pending_request = read_json(PENDING_PERMISSION_FILE)
    state = read_json(RUN_STATE_FILE, {"status": "NOT_STARTED"})
    state_request = state.get("permission_request")
    pending_result = state.get("pending_permission_result")
    candidate = pending_request if pending_request is not None else state_request
    if not isinstance(candidate, dict) and isinstance(pending_result, dict):
        request_id = pending_result.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
            raise RuntimeError("待投递权限结果的 request_id 无效")
        archive_path = permission_archive_path(request_id)
        if not archive_path.is_file():
            raise RuntimeError(f"待投递权限结果缺少归档：{request_id}")
        archive = read_json(archive_path)
        archived_request = archive.get("request")
        result = archive.get("result")
        if not isinstance(archived_request, dict) or not isinstance(result, dict):
            raise RuntimeError(f"权限归档内容无效：{request_id}")
        expected_summary = permission_result_summary(archived_request, result, archive_path)
        if pending_result != expected_summary:
            raise RuntimeError(f"待投递权限结果与归档不一致：{request_id}")
        return pending_result
    if not isinstance(candidate, dict):
        return None
    request_id = candidate.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        return None
    archive_path = permission_archive_path(request_id)
    if not archive_path.is_file():
        return None
    archive = read_json(archive_path)
    archived_request = archive.get("request")
    result = archive.get("result")
    if archived_request != candidate or not isinstance(result, dict):
        raise RuntimeError(f"权限归档与待处理请求不一致：{request_id}")
    if "status" not in result:
        raise RuntimeError(f"权限归档缺少执行状态：{request_id}")
    if pending_request is not None:
        PENDING_PERMISSION_FILE.unlink()
    summary = permission_result_summary(candidate, result, archive_path)
    update_run_state(
        status="IDLE",
        permission_request=None,
        pending_permission_result=summary,
        last_permission_result=summary,
    )
    return summary


def consume_permission_result(result: Dict[str, Any]) -> None:
    state = read_json(RUN_STATE_FILE, {"status": "NOT_STARTED"})
    pending_result = state.get("pending_permission_result")
    if pending_result is None:
        return
    if not isinstance(pending_result, dict):
        raise RuntimeError("待投递权限结果格式无效")
    if pending_result.get("request_id") != result.get("request_id"):
        raise RuntimeError("待投递权限结果与 worker 收到的请求不一致")
    update_run_state(pending_permission_result=None)


def migrate_legacy_sandbox_recovery_request(value: Dict[str, Any]) -> Dict[str, Any]:
    if value.get("kind") != "human_action" or isinstance(value.get("authorization"), dict):
        return value
    searchable = " ".join(
        str(item)
        for item in (
            value.get("reason", ""),
            value.get("risk", ""),
            value.get("instructions", ""),
        )
    ).casefold()
    if not any(marker in searchable for marker in SANDBOX_RECOVERY_MARKERS):
        return value
    targets = value.get("targets")
    if not isinstance(targets, list) or not targets:
        return value
    state = validate_planning_documents()
    if state.next_task is None or state.next_task.task_id != value.get("task_id"):
        return value
    plan = parse_plan_file()
    task = plan.task(state.next_task.task_id)
    allowed = {
        normalized_match_value(normalize_project_pattern(path, "allowed_paths"))
        for path in task.allowed_paths
    }
    normalized_targets: List[str] = []
    for target in targets:
        if not isinstance(target, str):
            return value
        normalized = normalize_project_pattern(target, "targets")
        if normalized_match_value(normalized) not in allowed:
            return value
        normalized_targets.append(normalized)
    migrated = dict(value)
    migrated.update(
        {
            "kind": SANDBOX_RECOVERY_KIND,
            "targets": normalized_targets,
            "risk_level": "medium",
            "risk": "确认后监督器会持久备份并原子重建当前任务最小写入根内由 CodexSandbox 账户拥有的最外层目录及普通文件，使所有者回到脚本用户；目录树清单或文件哈希不一致时自动回滚",
            "workspace_root": task.workspace_root,
            "plan_digest": plan.digest,
        }
    )
    migrated.pop("instructions", None)
    atomic_write_json(PENDING_PERMISSION_FILE, migrated)
    print_color("已将旧式 ACL 人工操作请求升级为可执行的沙箱恢复请求。", Colors.YELLOW)
    return migrated


def normalize_scope_extension_path(value: str) -> str:
    normalized = normalize_project_pattern(value, "requested_paths")
    parts = normalized.split("/")
    if normalized != value or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("scope_extension requested_paths 必须是规范化的项目相对路径")
    if any(character in normalized for character in "*?["):
        raise ValueError("scope_extension requested_paths 只能是精确文件路径")
    if os.name == "nt" and any(
        ":" in part or part.rstrip(" .") != part for part in parts
    ):
        raise ValueError("scope_extension requested_paths 包含无效文件名")
    protected_parts = {
        normalized_match_value(part) for part in SCOPE_EXTENSION_PROTECTED_PARTS
    }
    if (
        normalized_match_value(normalized) == normalized_match_value(SCRIPT_NAME)
        or any(normalized_match_value(part) in protected_parts for part in parts)
    ):
        raise ValueError("scope_extension 不允许扩展到监督器或元数据文件")
    return normalized


def validate_scope_extension_target(value: str) -> str:
    normalized = normalize_scope_extension_path(value)
    parts = normalized.split("/")
    candidate = SCRIPT_DIR.joinpath(*parts)
    project_root = SCRIPT_DIR.resolve()

    current = SCRIPT_DIR
    for part in parts[:-1]:
        current /= part
        is_junction = getattr(current, "is_junction", None)
        if current.is_symlink() or (callable(is_junction) and is_junction()):
            raise RuntimeError(f"范围扩展目标的父目录不能是符号链接：{normalized}")
        if current.exists() and not current.is_dir():
            raise RuntimeError(f"范围扩展目标的父路径不是目录：{normalized}")

    if candidate.is_symlink():
        raise RuntimeError(f"范围扩展目标不能是符号链接：{normalized}")
    if candidate.exists():
        if not candidate.is_file():
            raise RuntimeError(f"范围扩展目标必须是普通文件或精确的新文件：{normalized}")
    elif not candidate.suffix:
        raise RuntimeError(f"新增范围扩展目标必须带有文件后缀：{normalized}")

    resolved = candidate.resolve(strict=False)
    if not path_is_within(resolved, project_root):
        raise RuntimeError(f"范围扩展目标越出项目目录：{normalized}")
    return normalized


def validate_permission_request(value: Dict[str, Any]) -> Dict[str, Any]:
    required = {"version", "request_id", "kind", "task_id", "reason", "targets", "risk_level", "risk"}
    missing = sorted(required - value.keys())
    if missing:
        raise ValueError(f"权限请求缺少字段：{', '.join(missing)}")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("权限请求 version 必须是 1")
    request_id = value["request_id"]
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise ValueError("权限请求 request_id 格式无效")
    if permission_request_id_is_archived(request_id):
        raise ValueError(f"权限请求 request_id 已被使用：{request_id}")
    for field_name in ("task_id", "reason", "risk"):
        if not isinstance(value[field_name], str) or not value[field_name].strip():
            raise ValueError(f"权限请求 {field_name} 必须是非空字符串")
    if value["kind"] not in {"command", "human_action", "scope_extension", SANDBOX_RECOVERY_KIND}:
        raise ValueError(
            "权限请求 kind 只能是 command、human_action、scope_extension 或 sandbox_recovery"
        )
    if value["risk_level"] not in {"low", "medium", "high"}:
        raise ValueError("权限请求 risk_level 只能是 low、medium 或 high")
    if (
        not isinstance(value["targets"], list)
        or not value["targets"]
        or not all(isinstance(item, str) and item.strip() for item in value["targets"])
    ):
        raise ValueError("权限请求 targets 必须是非空字符串数组")
    timeout_seconds = value.get("timeout_seconds", 1800)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 21600:
        raise ValueError("权限请求 timeout_seconds 必须在 1 到 21600 之间")
    if value["kind"] == "command":
        command = value.get("command")
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) and item and "\0" not in item for item in command)
        ):
            raise ValueError("command 权限请求必须提供非空字符串数组 command")
        if len(command) > 100:
            raise ValueError("权限请求 command 参数过多")
        cwd_value = value.get("cwd")
        if not isinstance(cwd_value, str) or not cwd_value.strip() or "\0" in cwd_value:
            raise ValueError("command 权限请求必须提供 cwd")
    elif value["kind"] == "human_action":
        permission_instructions_text(value.get("instructions"))
    elif value["kind"] == "scope_extension":
        requested_paths = value.get("requested_paths")
        if (
            not isinstance(requested_paths, list)
            or not requested_paths
            or len(requested_paths) > 20
            or not all(isinstance(path, str) and path.strip() for path in requested_paths)
        ):
            raise ValueError("scope_extension 必须提供 1 到 20 个 requested_paths")
        normalized_requested_paths = set()
        for requested_path in requested_paths:
            normalized = normalize_scope_extension_path(requested_path)
            match_value = normalized_match_value(normalized)
            if match_value in normalized_requested_paths:
                raise ValueError("scope_extension requested_paths 不允许重复")
            normalized_requested_paths.add(match_value)
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("plan_digest", ""))):
            raise ValueError("scope_extension plan_digest 格式无效")
    else:
        workspace_root = value.get("workspace_root")
        if not isinstance(workspace_root, str):
            raise ValueError("sandbox_recovery 必须提供 workspace_root")
        normalized_workspace_root = normalize_project_pattern(workspace_root, "workspace_root")
        if normalized_workspace_root != workspace_root or any(
            character in workspace_root for character in "*?["
        ):
            raise ValueError("sandbox_recovery workspace_root 必须是规范化的精确项目相对目录")
        if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("plan_digest", ""))):
            raise ValueError("sandbox_recovery plan_digest 格式无效")
        for target in value["targets"]:
            normalized_target = normalize_project_pattern(target, "targets")
            if normalized_target != target or any(character in target for character in "*?["):
                raise ValueError("sandbox_recovery targets 只能包含规范化的精确项目相对文件")
    authorization = value.get("authorization")
    if authorization is not None:
        if value["kind"] != "human_action" or not isinstance(authorization, dict):
            raise ValueError("authorization 只能用于 human_action 请求")
        if authorization.get("area") != AUTHORIZATION_AREA:
            raise ValueError("authorization area 与监督脚本不一致")
        if not re.fullmatch(r"[0-9a-f]{64}", str(authorization.get("plan_digest", ""))):
            raise ValueError("authorization plan_digest 格式无效")
        allowed_scopes = authorization.get("allowed_scopes")
        if (
            not isinstance(allowed_scopes, list)
            or not allowed_scopes
            or not all(isinstance(scope, str) for scope in allowed_scopes)
        ):
            raise ValueError("authorization 必须提供 allowed_scopes")
        if len(set(allowed_scopes)) != len(allowed_scopes):
            raise ValueError("authorization allowed_scopes 不允许重复")
        if not set(allowed_scopes).issubset({"task", "plan"}):
            raise ValueError("authorization allowed_scopes 只能包含 task 和 plan")
    return value


def read_pending_permission() -> Optional[Dict[str, Any]]:
    recover_archived_permission()
    if not PENDING_PERMISSION_FILE.exists() and not PENDING_PERMISSION_FILE.is_symlink():
        return None
    if PENDING_PERMISSION_FILE.is_symlink() or not PENDING_PERMISSION_FILE.is_file():
        raise ValueError("PERMISSION_REQUEST.json 必须是普通文件")
    value = migrate_legacy_sandbox_recovery_request(read_json(PENDING_PERMISSION_FILE))
    return validate_permission_request(value)


def scope_extension_workspace_root(task: PlanTask, requested_paths: Sequence[str]) -> str:
    roots = [workspace_root_path(task)]
    for requested_path in requested_paths:
        normalized = normalize_project_pattern(requested_path, "requested_paths")
        roots.append((SCRIPT_DIR / Path(*normalized.split("/"))).resolve().parent)
    expanded = Path(os.path.commonpath(tuple(str(root) for root in roots))).resolve()
    if not path_is_within(expanded, SCRIPT_DIR.resolve()):
        raise RuntimeError("范围扩展后的 workspace_root 越出项目目录")
    relative = project_relative_path(expanded)
    return relative if relative else "."


def print_permission_request_details(request: Dict[str, Any]) -> None:
    authorization = request.get("authorization")
    if request["kind"] == "command":
        permission_source = "沙箱外命令"
    elif request["kind"] == SANDBOX_RECOVERY_KIND:
        permission_source = "Windows 沙箱写入恢复"
    elif request["kind"] == "scope_extension":
        permission_source = "任务允许路径扩展"
    elif isinstance(authorization, dict):
        permission_source = "项目规则"
    else:
        permission_source = "需要人工介入的操作"
    print_color(f"请求 ID：{request['request_id']}", Colors.CYAN)
    print_color(f"任务：{request['task_id']}", Colors.CYAN)
    print_color(f"权限来源：{permission_source}", Colors.CYAN)
    print_console_block("原因", request["reason"], Colors.CYAN)
    print_console_block("涉及位置或资源", "\n".join(request["targets"]), Colors.YELLOW)
    print_console_block(
        "风险",
        f"{request['risk_level']}：{request['risk']}",
        Colors.YELLOW,
    )
    if request["kind"] == "command":
        print_console_block(
            "受限操作",
            json.dumps(request["command"], ensure_ascii=False),
            Colors.YELLOW,
        )
        print_color(f"执行目录：{request['cwd']}", Colors.YELLOW)
    elif request["kind"] == "scope_extension":
        print_console_block(
            "建议加入 allowed_paths",
            "\n".join(request["requested_paths"]),
            Colors.YELLOW,
        )
        try:
            plan = parse_plan_file()
            task = plan.task(request["task_id"])
            proposed_workspace_root = scope_extension_workspace_root(
                task, request["requested_paths"]
            )
            if proposed_workspace_root != task.workspace_root:
                print_console_block(
                    "workspace_root 将扩大",
                    f"{task.workspace_root} -> {proposed_workspace_root}",
                    Colors.YELLOW,
                )
        except (FileNotFoundError, KeyError, RuntimeError, StopIteration, ValueError):
            pass
    elif request["kind"] == SANDBOX_RECOVERY_KIND:
        print_console_block("任务写入根", request["workspace_root"], Colors.YELLOW)
        print_console_block(
            "恢复方式",
            "监督器先回滚中断的旧式 ACL 修改，再持久备份并原子重建当前任务最小写入根内仅由 CodexSandbox 账户拥有的最外层目录及普通文件；目录树清单或文件哈希不变后自动重试。",
            Colors.YELLOW,
        )
    elif isinstance(authorization, dict):
        print_console_block("需要确认", permission_instructions_text(request["instructions"]), Colors.YELLOW)
    else:
        print_console_block("人工操作", permission_instructions_text(request["instructions"]), Colors.YELLOW)


def wait_for_permission_resolution(expected_task_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    try:
        recovered_result = recover_archived_permission()
        if recovered_result is not None:
            print_color(
                f"已恢复完成的权限归档：{recovered_result['request_id']}。",
                Colors.YELLOW,
            )
            return recovered_result
        request = read_pending_permission()
    except ValueError as error:
        result = quarantine_invalid_permission_request(error, expected_task_id)
        print_color(f"无效权限请求已隔离：{error}", Colors.RED)
        return result
    if request is None:
        return None
    if request["kind"] == SANDBOX_RECOVERY_KIND:
        rollback_interrupted_sandbox_recovery(request)
    if expected_task_id is not None and request["task_id"] != expected_task_id:
        error = ValueError(
            f"权限请求任务 {request['task_id']} 与当前任务 {expected_task_id} 不一致"
        )
        archive_invalid_permission_payload(request, error)
        print_color(f"无效权限请求已归档：{error}", Colors.RED)
        return read_json(RUN_STATE_FILE).get("last_permission_result")
    if request["kind"] == "command":
        try:
            cwd = resolve_permission_cwd(request)
            resolve_permission_executable(request["command"], cwd, os.environ.copy())
        except PermissionExecutableError as error:
            archive_invalid_permission_request(request, error)
            print_color(f"无效权限请求已归档：{error}", Colors.RED)
            return read_json(RUN_STATE_FILE).get("last_permission_result")
    request_id = request["request_id"]
    update_run_state(status="WAITING_APPROVAL", permission_request=request)
    receipt_authorizes_plan = confirmed_scope_approval(request)
    if receipt_authorizes_plan is not None:
        print_color(
            f"请求 {request_id} 与上次失败前的人工确认回执完全一致，正在恢复执行。",
            Colors.GREEN,
        )
        approve_request(
            request_id,
            authorize_plan=receipt_authorizes_plan,
            approved_by_confirmation_receipt=True,
        )
        recovered_result = recover_archived_permission()
        if isinstance(recovered_result, dict):
            return recovered_result
        raise RuntimeError(f"确认回执请求 {request_id} 已执行，但缺少归档结果")
    if permission_request_has_plan_grant(request):
        print_color(
            f"请求 {request_id} 与当前计划已授权的精确指纹一致，正在自动批准。",
            Colors.GREEN,
        )
        approve_request(request_id, approved_by_plan_grant=True)
        recovered_result = recover_archived_permission()
        if isinstance(recovered_result, dict):
            return recovered_result
        raise RuntimeError(f"计划授权请求 {request_id} 已执行，但缺少归档结果")
    print_color("当前任务需要获取权限或人工确认，Codex 子进程已退出。", Colors.YELLOW)
    print_permission_request_details(request)
    authorization = request.get("authorization")
    play_permission_alert()
    if sys.stdin.isatty():
        handle_permission_in_current_terminal(request)
    else:
        raise InteractiveInputUnavailableError(
            "当前没有可交互终端，权限请求仍保留；请在可交互终端中运行脚本"
        )
    if isinstance(authorization, dict):
        last_result = read_json(RUN_STATE_FILE).get("last_permission_result")
        if isinstance(last_result, dict) and last_result.get("request_id") == request_id:
            if last_result.get("status") == "denied":
                consume_permission_result(last_result)
                reason = f"用户拒绝了 {AUTHORIZATION_AREA_LABEL} 授权"
                update_run_state(status="PAUSED_AUTHORIZATION_DENIED", pause_reason=reason)
                raise AuthorizationDeniedError(reason)
    if request["kind"] == "scope_extension":
        last_result = read_json(RUN_STATE_FILE).get("last_permission_result")
        if isinstance(last_result, dict) and last_result.get("request_id") == request_id:
            if last_result.get("status") == "denied":
                consume_permission_result(last_result)
                reason = f"用户拒绝扩展任务 {request['task_id']} 的 allowed_paths"
                update_run_state(status="PAUSED_SCOPE_EXTENSION_DENIED", pause_reason=reason)
                raise AuthorizationDeniedError(reason)
    if request["kind"] == SANDBOX_RECOVERY_KIND:
        last_result = read_json(RUN_STATE_FILE).get("last_permission_result")
        if isinstance(last_result, dict) and last_result.get("request_id") == request_id:
            if last_result.get("status") == "denied":
                consume_permission_result(last_result)
                reason = f"用户拒绝恢复任务 {request['task_id']} 的 Windows 沙箱 ACL"
                update_run_state(status="PAUSED_SANDBOX_RECOVERY_DENIED", pause_reason=reason)
                raise AuthorizationDeniedError(reason)
    recovered_result = recover_archived_permission()
    if isinstance(recovered_result, dict) and recovered_result.get("request_id") == request_id:
        return recovered_result
    raise RuntimeError(f"权限请求 {request_id} 已结束，但缺少执行结果")


def request_looks_high_risk(request: Dict[str, Any]) -> bool:
    if request["risk_level"] == "high":
        return True
    if request["kind"] != "command":
        return False
    normalized_arguments = [argument.strip().lower() for argument in request["command"]]
    executable_suffix = Path(normalized_arguments[0]).suffix
    if executable_suffix in MUTABLE_SCRIPT_SUFFIXES:
        return True
    normalized_names = {Path(argument).name.removesuffix(".exe") for argument in normalized_arguments}
    joined = " ".join(normalized_arguments)
    for token in HIGH_RISK_TOKENS:
        if token in normalized_names or token in normalized_arguments:
            return True
        token_pattern = r"\s+".join(re.escape(part) for part in token.split())
        if re.search(rf"(?<![\w-]){token_pattern}(?![\w-])", joined):
            return True
    return False


def request_uses_shell(request: Dict[str, Any]) -> bool:
    if request["kind"] != "command":
        return False
    executable = Path(request["command"][0]).name.lower()
    return executable in SHELL_EXECUTABLES


def archive_invalid_permission_request(
    request: Dict[str, Any],
    error: PermissionExecutableError,
) -> None:
    archive_permission(
        request,
        {
            "version": 1,
            "request_id": request["request_id"],
            "task_id": request["task_id"],
            "status": "invalid_request",
            "failure_kind": error.failure_kind,
            "executable": error.executable,
            "cwd": str(error.cwd),
            "finished_at": now_iso(),
            "note": str(error),
        },
    )


def archive_invalid_permission_payload(
    request: Dict[str, Any],
    error: ValueError,
) -> bool:
    request_id = request.get("request_id")
    task_id = request.get("task_id")
    if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
        return False
    if not isinstance(task_id, str) or not task_id.strip():
        return False
    if permission_request_id_is_archived(request_id):
        return False
    archive_permission(
        request,
        {
            "version": 1,
            "request_id": request_id,
            "task_id": task_id,
            "status": "invalid_request",
            "failure_kind": "invalid_request",
            "finished_at": now_iso(),
            "note": str(error),
        },
    )
    return True


def quarantine_invalid_permission_request(
    error: ValueError,
    expected_task_id: Optional[str],
) -> Dict[str, Any]:
    ensure_runtime_directories()
    archive_name = (
        f"INVALID-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}.json"
    )
    archive_path = PERMISSION_ARCHIVE_DIR / archive_name
    if PENDING_PERMISSION_FILE.is_symlink():
        link_target = os.readlink(PENDING_PERMISSION_FILE)
        atomic_write_json(
            archive_path,
            {
                "version": 1,
                "status": "invalid_request",
                "entry_type": "symlink",
                "link_target": link_target,
                "note": str(error),
                "archived_at": now_iso(),
            },
        )
        PENDING_PERMISSION_FILE.unlink(missing_ok=True)
    elif PENDING_PERMISSION_FILE.is_file():
        os.replace(PENDING_PERMISSION_FILE, archive_path)
    elif PENDING_PERMISSION_FILE.exists():
        atomic_write_json(
            archive_path,
            {
                "version": 1,
                "status": "invalid_request",
                "entry_type": "directory" if PENDING_PERMISSION_FILE.is_dir() else "other",
                "note": str(error),
                "archived_at": now_iso(),
            },
        )
        remove_for_restore(PENDING_PERMISSION_FILE)
    else:
        atomic_write_json(
            archive_path,
            {
                "version": 1,
                "status": "invalid_request",
                "entry_type": "missing",
                "note": str(error),
                "archived_at": now_iso(),
            },
        )
    result = {
        "request_id": None,
        "task_id": expected_task_id,
        "kind": "invalid",
        "status": "invalid_request",
        "note": str(error),
        "result_file": str(archive_path.relative_to(SCRIPT_DIR)),
    }
    update_run_state(
        status="IDLE",
        permission_request=None,
        last_permission_result=result,
    )
    return result


_active_approval_lock: Optional[Any] = None


def claim_approval(request: Dict[str, Any], action: str) -> None:
    global _active_approval_lock
    if _active_approval_lock is not None:
        raise RuntimeError("当前进程已经持有授权处理锁")
    claim = {
        "request_id": request["request_id"],
        "pid": os.getpid(),
        "lock_id": uuid.uuid4().hex,
        "created_at": now_iso(),
        "action": action,
        "request_digest": permission_request_digest(request),
    }
    lock_context = exclusive_file_lock(
        APPROVAL_CLAIM_FILE,
        "已有另一个授权处理进程正在运行",
        claim,
    )
    lock_context.__enter__()
    _active_approval_lock = lock_context


def release_approval_claim() -> None:
    global _active_approval_lock
    lock_context = _active_approval_lock
    _active_approval_lock = None
    if lock_context is not None:
        lock_context.__exit__(None, None, None)


def confirmed_scope_approval(request: Dict[str, Any]) -> Optional[bool]:
    if request.get("kind") != "scope_extension":
        return None
    if APPROVAL_CLAIM_FILE.is_symlink() or not APPROVAL_CLAIM_FILE.is_file():
        return None
    try:
        claim = read_json(APPROVAL_CLAIM_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    action = claim.get("action")
    if action not in {"approve_task", "approve_plan"}:
        return None
    if claim.get("request_id") != request.get("request_id"):
        return None
    if claim.get("request_digest") != permission_request_digest(request):
        return None
    return action == "approve_plan"


def archive_permission(request: Dict[str, Any], result: Dict[str, Any]) -> None:
    request_id = request["request_id"]
    archive_path = permission_archive_path(request_id)
    if archive_path.exists():
        raise RuntimeError(f"拒绝覆盖已有权限归档：{request_id}")
    atomic_write_json(
        archive_path,
        {
            "version": 1,
            "request": request,
            "result": result,
        },
    )
    PENDING_PERMISSION_FILE.unlink()
    result_summary = permission_result_summary(request, result, archive_path)
    update_run_state(
        status="IDLE",
        permission_request=None,
        pending_permission_result=result_summary,
        last_permission_result=result_summary,
    )


def require_live_waiting_supervisor(request_id: str) -> None:
    try:
        supervisor_metadata = read_json(SUPERVISOR_METADATA_FILE)
        process_id = int(supervisor_metadata.get("pid", 0))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("监督脚本没有运行，不能处理一次性授权") from error
    if not process_is_alive(process_id):
        raise RuntimeError("监督脚本没有运行，不能处理一次性授权")
    run_state = read_json(RUN_STATE_FILE)
    permission_request = run_state.get("permission_request")
    if run_state.get("status") != "WAITING_APPROVAL" or not isinstance(permission_request, dict):
        raise RuntimeError("监督脚本当前不处于等待授权状态")
    if permission_request.get("request_id") != request_id:
        raise RuntimeError("监督脚本等待的请求 ID 与当前请求不一致")


def require_interactive_confirmation(action: str, request_id: str) -> None:
    if not sys.stdin.isatty():
        raise RuntimeError("一次性授权必须由用户在交互式终端确认，拒绝无头或管道输入")
    expected = f"{action} {request_id}"
    print_color(f"为防止模型自我授权，请手动输入：{expected}", Colors.YELLOW)
    actual = read_terminal_input("> ").strip()
    if actual != expected:
        raise ConfirmationMismatchError("确认文本不匹配，本次请求未处理")


def record_scope_extension(request: Dict[str, Any]) -> Tuple[Tuple[str, ...], str]:
    state = validate_planning_documents()
    if state.next_task is None or state.next_task.task_id != request["task_id"]:
        raise RuntimeError("范围扩展请求对应的任务已不是当前任务")
    plan = parse_plan_file()
    if plan.digest != request["plan_digest"]:
        raise RuntimeError("PLAN.md 已变化，本次范围扩展请求已失效")
    plan_task = plan.task(request["task_id"])
    authorization_context = build_authorization_context(plan_task, plan=plan)
    authorization_scope = matching_authorization_scope(state.next_task, authorization_context)
    normalized_paths: List[str] = []
    for requested_path in request["requested_paths"]:
        normalized = validate_scope_extension_target(requested_path)
        if path_matches_allowed(normalized, plan_task.allowed_paths):
            raise RuntimeError(f"范围扩展目标已在 allowed_paths 中：{normalized}")
        normalized_paths.append(normalized)
    expanded_workspace_root = scope_extension_workspace_root(plan_task, normalized_paths)

    original_content = PLAN_FILE.read_text(encoding="utf-8")
    plan_value = extract_plan_data(original_content)
    raw_tasks = plan_value.get("tasks")
    if not isinstance(raw_tasks, list):
        raise RuntimeError("PLAN.md tasks 格式无效")
    raw_task = next(
        (
            item
            for item in raw_tasks
            if isinstance(item, dict) and item.get("id") == request["task_id"]
        ),
        None,
    )
    if (
        raw_task is None
        or not isinstance(raw_task.get("allowed_paths"), list)
        or not isinstance(raw_task.get("workspace_root"), str)
    ):
        raise RuntimeError("PLAN.md 当前任务 workspace_root 或 allowed_paths 格式无效")
    raw_task["workspace_root"] = expanded_workspace_root
    raw_task["allowed_paths"].extend(normalized_paths)
    atomic_write_text(PLAN_FILE, replace_plan_data(original_content, plan_value))
    try:
        updated_state = validate_planning_documents()
        updated_plan = parse_plan_file()
        updated_task = updated_plan.task(request["task_id"])
        updated_context = build_authorization_context(updated_task, plan=updated_plan)
        rebind_plan_permission_grants(plan.digest, updated_plan.digest)
    except Exception:
        atomic_write_text(PLAN_FILE, original_content)
        raise

    if (
        authorization_scope is not None
        and updated_state.next_task is not None
        and updated_state.next_task.task_id == request["task_id"]
        and set(updated_context.matches).issubset(authorization_context.matches)
    ):
        authorization = read_json(AUTHORIZATION_FILE)
        authorization["plan_digest"] = authorization_context_digest(updated_context)
        authorization["updated_at"] = now_iso()
        authorization["updated_by_scope_request"] = request["request_id"]
        atomic_write_json(AUTHORIZATION_FILE, authorization)
    return tuple(normalized_paths), expanded_workspace_root


def execute_permission_command(
    request: Dict[str, Any],
    approval_message: str,
) -> Dict[str, Any]:
    cwd = resolve_permission_cwd(request)
    execution_stage = "resolve_executable"
    try:
        executable = resolve_permission_executable(request["command"], cwd, os.environ.copy())
        execution_command = [executable, *request["command"][1:]]
        execution_stage = "approval_notice"
        print_color(approval_message, Colors.YELLOW)
        execution_stage = "process_runtime_or_cleanup"
        process_result = run_process(
            execution_command,
            cwd,
            os.environ.copy(),
            min(int(request.get("timeout_seconds", 1800)), 1800),
            int(request.get("timeout_seconds", 1800)),
            f"approval-{request['request_id']}",
        )
    except PermissionExecutableError as error:
        return {
            "version": 1,
            "request_id": request["request_id"],
            "task_id": request["task_id"],
            "status": "failed",
            "failure_kind": error.failure_kind,
            "executable": error.executable,
            "cwd": str(error.cwd),
            "finished_at": now_iso(),
            "note": str(error),
            "failure_summary": {
                "command": list(request["command"]),
                "cwd": str(error.cwd),
                "stage": "resolve_executable",
                "core_error": str(error),
            },
        }
    except ProcessStartError as start_error:
        error = start_error.error
        return {
            "version": 1,
            "request_id": request["request_id"],
            "task_id": request["task_id"],
            "status": "failed",
            "failure_kind": (
                "executable_not_found"
                if isinstance(error, FileNotFoundError)
                else "process_start_failed"
            ),
            "executable": request["command"][0],
            "cwd": str(cwd),
            "finished_at": now_iso(),
            "note": str(error),
            "failure_summary": {
                "command": list(request["command"]),
                "cwd": str(cwd),
                "stage": "process_start",
                "core_error": f"{type(error).__name__}: {error}",
            },
        }
    except OSError as error:
        return {
            "version": 1,
            "request_id": request["request_id"],
            "task_id": request["task_id"],
            "status": "failed",
            "failure_kind": "supervisor_runtime_failed",
            "executable": request["command"][0],
            "cwd": str(cwd),
            "finished_at": now_iso(),
        "note": f"{type(error).__name__}: {error}",
        "failure_summary": {
            "command": list(request["command"]),
            "cwd": str(cwd),
            "stage": execution_stage,
            "core_error": f"{type(error).__name__}: {error}",
        },
        }
    result = {
        "version": 1,
        "request_id": request["request_id"],
        "task_id": request["task_id"],
        "status": "succeeded" if process_result.return_code == 0 else "failed",
        "finished_at": now_iso(),
        "return_code": process_result.return_code,
        "timed_out": process_result.timed_out,
        "timeout_reason": process_result.timeout_reason,
        "log_file": str(process_result.log_file.relative_to(SCRIPT_DIR)),
    }
    if process_result.return_code != 0 or process_result.timed_out:
        output_tail = command_failure_tail(process_result.output_tail, PROCESS_OUTPUT_TAIL_LINES)
        core_error = process_result.retry_summary.core_error or command_failure_tail(
            process_result.output_tail,
            20,
        )
        result["failure_summary"] = {
            "command": list(request["command"]),
            "cwd": str(cwd),
            "core_error": core_error,
            "output_tail": output_tail,
        }
    return result


def approve_request(
    request_id: str,
    authorize_plan: bool = False,
    approved_by_plan_grant: bool = False,
    approved_by_confirmation_receipt: bool = False,
) -> int:
    ensure_runtime_directories()
    request = read_pending_permission()
    if request is None:
        print_color("当前没有待处理的权限请求。", Colors.YELLOW)
        return 1
    if request["request_id"] != request_id:
        print_color(f"请求 ID 不匹配，当前请求是 {request['request_id']}。", Colors.RED)
        return 1
    require_live_waiting_supervisor(request["request_id"])
    if request["kind"] == "command":
        try:
            preflight_cwd = resolve_permission_cwd(request)
            resolve_permission_executable(request["command"], preflight_cwd, os.environ.copy())
        except PermissionExecutableError as error:
            claim_approval(request, "archive_invalid")
            try:
                archive_invalid_permission_request(request, error)
            finally:
                release_approval_claim()
            print_color(f"无效权限请求已归档：{error}", Colors.RED)
            return 2
    if approved_by_plan_grant and approved_by_confirmation_receipt:
        raise RuntimeError("计划指纹授权与确认回执不能同时启用")
    if authorize_plan and approved_by_plan_grant:
        raise RuntimeError("计划级人工授权与自动授权不能同时启用")
    authorization = request.get("authorization")
    authorization_scope = "plan" if authorize_plan or approved_by_plan_grant else "task"
    if authorize_plan:
        confirmation_action = "APPROVE PLAN"
    elif request["kind"] == "scope_extension":
        confirmation_action = "APPROVE SCOPE"
    elif request["kind"] == SANDBOX_RECOVERY_KIND:
        confirmation_action = "APPROVE SANDBOX"
    else:
        confirmation_action = "APPROVE"
    if approved_by_confirmation_receipt:
        receipt_authorizes_plan = confirmed_scope_approval(request)
        if receipt_authorizes_plan is None or receipt_authorizes_plan != authorize_plan:
            raise RuntimeError("当前范围扩展请求没有匹配的人工确认回执")
    elif approved_by_plan_grant:
        if not permission_request_has_plan_grant(request):
            raise RuntimeError("当前请求没有匹配的计划级精确指纹授权")
    else:
        require_interactive_confirmation(confirmation_action, request["request_id"])
    if approved_by_plan_grant:
        approval_action = "auto_plan_grant"
    elif authorize_plan:
        approval_action = "approve_plan"
    else:
        approval_action = "approve_task"
    claim_approval(request, approval_action)
    try:
        if request["kind"] == "scope_extension":
            added_paths, workspace_root = record_scope_extension(request)
            result_value = {
                "version": 1,
                "request_id": request["request_id"],
                "task_id": request["task_id"],
                "status": "scope_extended",
                "finished_at": now_iso(),
                "added_paths": list(added_paths),
                "workspace_root": workspace_root,
                "note": "用户同意将建议文件加入当前任务 allowed_paths",
            }
        elif request["kind"] == SANDBOX_RECOVERY_KIND:
            result_value = repair_sandbox_acl(request)
        elif request["kind"] == "human_action":
            if isinstance(authorization, dict):
                record_authorization_grant(request, authorization_scope)
            result_value = {
                "version": 1,
                "request_id": request["request_id"],
                "task_id": request["task_id"],
                "status": "confirmed",
                "confirmed_at": now_iso(),
                "note": "用户已确认完成人工操作",
            }
            if isinstance(authorization, dict):
                result_value["authorization_scope"] = authorization_scope
        else:
            if approved_by_plan_grant:
                approval_message = "正在执行与当前计划精确指纹授权一致的命令。"
            elif authorize_plan:
                approval_message = "正在执行本次命令，并为当前计划记录其精确权限指纹。"
            else:
                approval_message = "正在执行这一次明确批准的命令，不会授予后续会话通用权限。"
            result_value = execute_permission_command(request, approval_message)
        result_value["authorization_scope"] = authorization_scope
        if approved_by_plan_grant:
            result_value["permission_fingerprint"] = permission_request_fingerprint(request)
            result_value["auto_approved"] = True
        elif authorize_plan:
            result_value["permission_fingerprint"] = permission_request_fingerprint(request)
            result_value["auto_approved"] = False
        archive_permission(request, result_value)
        if authorize_plan:
            record_plan_permission_grant(request)
        if request["kind"] == "scope_extension":
            print_color("建议文件已加入当前任务 allowed_paths，主循环将自动恢复。", Colors.GREEN)
        elif request["kind"] == SANDBOX_RECOVERY_KIND:
            print_color("当前任务已切换为隔离工作目录和最小写入根，主循环将自动重试。", Colors.GREEN)
        elif approved_by_plan_grant:
            print_color("当前请求已由计划级精确指纹授权自动批准，主循环将自动恢复。", Colors.GREEN)
        elif authorize_plan:
            print_color("当前请求指纹已授权用于本计划，主循环将自动恢复。", Colors.GREEN)
        else:
            print_color(f"一次性请求 {request['request_id']} 已处理，主循环将自动恢复。", Colors.GREEN)
        return 0
    finally:
        release_approval_claim()


def deny_request(request_id: str) -> int:
    ensure_runtime_directories()
    request = read_pending_permission()
    if request is None:
        print_color("当前没有待处理的权限请求。", Colors.YELLOW)
        return 1
    if request["request_id"] != request_id:
        print_color(f"请求 ID 不匹配，当前请求是 {request['request_id']}。", Colors.RED)
        return 1
    require_live_waiting_supervisor(request["request_id"])
    require_interactive_confirmation("DENY", request["request_id"])
    claim_approval(request, "deny")
    try:
        archive_permission(
            request,
            {
                "version": 1,
                "request_id": request["request_id"],
                "task_id": request["task_id"],
                "status": "denied",
                "finished_at": now_iso(),
                "note": "用户拒绝了这次请求",
            },
        )
        if request["kind"] == "scope_extension":
            print_color(
                f"已拒绝添加建议文件，任务 {request['task_id']} 将暂停且不会修改 allowed_paths。",
                Colors.YELLOW,
            )
        elif request["kind"] == SANDBOX_RECOVERY_KIND:
            print_color(
                f"已拒绝恢复任务 {request['task_id']} 的沙箱 ACL，任务将保持暂停。",
                Colors.YELLOW,
            )
        else:
            print_color(
                f"已拒绝一次性请求 {request['request_id']}，主循环将重新规划安全路径。",
                Colors.YELLOW,
            )
        return 0
    finally:
        release_approval_claim()


def handle_permission_in_current_terminal(request: Dict[str, Any]) -> None:
    request_id = request["request_id"]
    stop_reminder = threading.Event()

    def remind() -> None:
        while not stop_reminder.wait(PERMISSION_ALERT_REPEAT_SECONDS):
            if not PENDING_PERMISSION_FILE.exists():
                return
            print_color(f"仍在等待一次性授权：{request_id}", Colors.DARK_GRAY)
            play_permission_alert()

    reminder = threading.Thread(target=remind, name="permission-reminder", daemon=True)
    reminder.start()
    try:
        while PENDING_PERMISSION_FILE.exists():
            print_color("请直接在当前终端选择：", Colors.CYAN)
            for option, label in PERMISSION_MENU_OPTIONS:
                safe_print(f"  {option}. {label}", flush=True)
            if request_looks_high_risk(request):
                print_color("     注意：该请求被识别为高风险！", Colors.RED)
            if request_uses_shell(request):
                print_color("     注意：该命令会启动通用命令解释器！", Colors.RED)
            choice = read_terminal_input("请选择：").strip().lower()
            try:
                if choice == "1":
                    result = approve_request(request_id)
                elif choice == "2":
                    result = approve_request(request_id, authorize_plan=True)
                elif choice == "3":
                    result = deny_request(request_id)
                else:
                    print_color("请输入 1、2 或 3。", Colors.YELLOW)
                    continue
            except ConfirmationMismatchError as error:
                print_color(str(error), Colors.RED)
                continue
            except RuntimeError as error:
                print_color(str(error), Colors.RED)
                raise
            if result == 0:
                return
    finally:
        stop_reminder.set()


def show_status() -> int:
    state = read_json(RUN_STATE_FILE, {"status": "NOT_STARTED"})
    safe_print(json.dumps(state, ensure_ascii=False, indent=2))
    request = read_pending_permission()
    if request:
        safe_print("\n待处理权限请求：")
        print_permission_request_details(request)
    try:
        snapshot = parse_state_file()
        safe_print(f"\n任务进度：{snapshot.completed_count}/{len(snapshot.tasks)}")
        if snapshot.next_task:
            safe_print(f"下一任务：{snapshot.next_task.task_id} {snapshot.next_task.title}")
    except (FileNotFoundError, ValueError) as error:
        safe_print(f"\n规划状态：{error}")
    return 0


def show_usage_help() -> int:
    help_text = f"""
{SCRIPT_NAME} 是一个安全、可断点续跑的 Codex 自动化监督脚本。建议先安装 git 再运行。

常用命令

  python {SCRIPT_NAME}
      启动自动化。已有 planning/RULES.md、planning/PLAN.md、worker-control/STATE.md 时，会从第一个未完成任务继续。

  python {SCRIPT_NAME} --model <模型名> --effort <推理力度>
      使用指定模型和推理力度启动或续跑。两个参数可以单独使用，命令行值优先于脚本内置默认值。
      --effort 可选值：low、medium、high、xhigh。

  python {SCRIPT_NAME} status
      查看当前状态、任务进度、待处理权限请求。

  python {SCRIPT_NAME} help
      显示本说明。

首次创建项目

  1. 初始只需要 {SCRIPT_NAME}；把完整需求填写到脚本顶部的 PROJECT_REQUIREMENTS。
  2. 执行 python {SCRIPT_NAME}，不需要 run 参数。
  3. 脚本读取内嵌需求，在运行目录 .codex-automation 中生成可恢复状态并逐项执行。
  4. PROJECT_REQUIREMENTS 为空时，仍可在交互式终端粘贴需求，并用单独一行 [END] 结束。

停止与续跑

  关闭终端或按 Ctrl+C 即停止。再次执行 python {SCRIPT_NAME} 就会根据 .codex-automation/worker-control/STATE.md 自动续跑。
  达到内置的连续失败或无进展阈值时，本次进程会退出，检查原因后直接重新运行即可。

完成轮次的处理

  如果三份核心文档都存在、内容非空且任务全部完成，会提供两个选项：
  1. 归档：把当前未归档轮次整体移动到 .codex-automation/年月日时分秒/；
  2. 删除：只删除当前未归档轮次，所有已有归档目录保持不变。

  如果三份核心文档缺失、存在空文件、内容无效，则不允许归档，只提供删除选项。

权限不足与批准的关系

  1. Codex 始终运行在 workspace-write 沙箱中，不能自行获取更高权限；
  2. 某项操作无法在沙箱内完成时，Codex 负责写入 PERMISSION_REQUEST.json 后退出；如果 Windows sandbox refresh 在 worker 启动前失败，连控制文件也无法写入，监督器会根据结构化失败自动生成 sandbox_recovery 请求。请求必须写明权限来源、实际拒绝原因，以及具体文件、目录、服务、系统资源；
  3. 监督脚本停止启动新任务，在当前终端显示权限来源、原因、涉及位置、执行目录和风险，并等待你的决定，不会自动批准。
     此时会播放特殊的提醒旋律，并每 5 分钟重复提醒一次；
  4. 每个请求固定提供三个选项：输入 1 批准当前请求；输入 2 记录该请求的计划级精确指纹授权；输入 3 拒绝当前请求。
     选择后仍需按屏幕提示输入完整确认文本，防止模型自动代理自我授权。
  5. 执行结束后当前请求立即失效；后续 command 请求只有在 PLAN 摘要、授权来源归档和精确指纹全部一致时才会自动批准，其他类型请求必须重新批准。
  6. 管理员/root/UAC、sudo、凭据输入、系统设置、高成本 API 不会自动执行，只会要求人工处理。
  7. scope_extension 人工确认后若监督器动作失败，会保存包含完整请求摘要的确认回执；重启时只恢复同一份范围请求，不会复用于其他请求类型。

任务允许路径扩展

  Worker 确认当前交付物必须修改 allowed_paths 外的现有文件，或必须新增精确的拆分文件时，会提交精确文件列表并退出，不能自行扩大范围。
  选择 1 并按提示输入 APPROVE SCOPE <请求ID> 后，
  脚本会校验文件、当前任务和 PLAN.md 摘要，再自动把这些文件加入当前任务 allowed_paths；如果新文件
  超出原 workspace_root，还会把 workspace_root 扩大到能够容纳原范围与新增文件的最小共同目录，然后继续执行；
  选择 2 并输入 APPROVE PLAN <请求ID> 会额外记录该范围请求的计划级精确指纹；选择 3 并输入 DENY <请求ID> 后，不修改 PLAN.md，并暂停当前任务。
  范围扩展接受项目内现有普通文件，或父路径安全且带文件后缀的精确新文件；不接受目录、通配符、符号链接、监督器/元数据文件或已允许的路径，也不会提前创建新文件。

Windows 沙箱恢复

  Worker 在当前 allowed_paths 内遇到 Windows ACL 或 Failed to write file 时提交 sandbox_recovery；如果 setup refresh 在 worker 启动前失败，导致 worker 连控制文件也无法写入，监督器会使用当前任务全部精确 allowed_paths 自动生成同类请求。两种情况都不能要求用户手工运行 icacls。
  选择 1 并输入 APPROVE SANDBOX <请求ID> 后，监督器先恢复任何中断的旧式 ACL 修改，再持久备份并原子重建当前任务最小写入根内仅由 CodexSandbox 账户拥有的最外层目录及普通文件；目录树清单或文件哈希不一致会立即回滚。
  选择 2 并输入 APPROVE PLAN <请求ID> 会额外记录该沙箱恢复请求的计划级精确指纹；选择 3 会拒绝并暂停当前任务。
  Worker 使用隔离工作目录，项目写权限只通过 allowed_paths 的最小父目录授予；每次会话结束后恢复会话前 ACL，避免临时沙箱 SID 累积。
  所有权恢复备份保存在 .codex-automation/permissions/ownership-backups/；会话 ACL 快照只恢复实际变化的 DACL，不同所有者且 DACL 未变化的文件会直接跳过。

授权范围

  每个权限请求固定显示三个选项：1 批准当前请求、2 授权整个计划请求、3 拒绝当前请求。
  选择 2 只记录当前请求的 SHA-256 精确指纹；命令请求的指纹包含请求类型、完整命令及参数、规范化工作目录和风险级别。
  后续 command 请求只有在当前 PLAN 摘要一致、授权来源请求已归档，且命令、参数、规范化工作目录和风险级别全部相同时才会自动批准；其他类型请求不会自动批准，高风险请求仍显示红色警告并要求首次手动确认。
  workspace_root 是任务范围边界；Worker 实际项目写入根由 allowed_paths 的最小父目录精确生成，allowed_paths 只列当前任务允许交付的精确文件；
  generated_paths 只列验证命令可能写入的显式目录树，统一使用 path/**，监督器不会根据技术栈或目录名推断。
  脚本依据 allowed_paths，从项目根目录向每个目标文件所在目录逐级收集适用的 AGENTS.md，
  并只从这些适用规则及当前 RULES.md 中识别修改前必须取得人工同意、批准或授权的要求。
  无关子目录的 AGENTS.md 不参与当前任务授权，也不需要配置项目专属目录名。
  对受项目规则保护的修改，选择 1 只授权当前任务；选择 2 同时授权当前计划内必要的受保护修改，并记录该请求的精确指纹。
  PLAN.md、RULES.md 或计划任务适用的 AGENTS.md 内容变化，以及当前轮次归档或删除后，
  计划级授权自动失效。
  旧版或规则摘要不匹配的待授权请求会自动失效并归档，再按当前规则生成新请求。
  精确指纹授权不会覆盖参数、目录或风险级别不同的后续请求，也不会扩大项目路径范围。
  AUTHORIZATION.json 只由监督脚本写入。工作会话修改或删除它时，监督脚本会立即暂停。

运行数据

  .codex-automation/planning/RULES.md        当前轮次规则
  .codex-automation/planning/PLAN.md         当前轮次计划
  .codex-automation/worker-control/STATE.md  当前轮次任务状态
  .codex-automation/RUN_STATE.json           监督状态
  .codex-automation/AUTHORIZATION.json       当前任务或当前计划的项目规则授权
  .codex-automation/logs/                    每轮完整日志，包括原始 JSON、完整命令输出和错误细节
  .codex-automation/worker-control/PERMISSION_REQUEST.json  当前待批准请求
  .codex-automation/permissions/             已处理请求及结果
  系统临时目录/autocodex-workspace-guards-*/  Worker 不可写的临时越界恢复备份

控制台输出

  控制台只显示经过整理的彩色任务摘要、思考、命令结果、权限详情、错误末尾，不直接输出 Codex JSON。
  控制台中省略的完整事件、命令输出、诊断信息始终保存在 .codex-automation/logs/。

Git 忽略规则

  如果脚本同级存在 .gitignore，启动时会自动确保忽略 /.codex-automation/ 和 /{SCRIPT_NAME}。
  已存在的规则不会重复添加，如果同级没有 .gitignore，脚本不会主动创建。
"""
    safe_print(help_text.strip())
    return 0


def state_transition_error(
    before: StateSnapshot,
    after: StateSnapshot,
    expected_task_id: str,
) -> Optional[str]:
    before_ids = tuple(task.task_id for task in before.tasks)
    after_ids = tuple(task.task_id for task in after.tasks)
    if before_ids != after_ids:
        return "STATE.md 的任务编号或顺序在工作会话中发生变化"
    before_titles = tuple(task.title for task in before.tasks)
    after_titles = tuple(task.title for task in after.tasks)
    if before_titles != after_titles:
        return "STATE.md 的任务名称在工作会话中发生变化"
    before_by_id = {task.task_id: task for task in before.tasks}
    reopened = [
        task.task_id
        for task in after.tasks
        if before_by_id[task.task_id].completed and not task.completed
    ]
    if reopened:
        return f"已完成任务被重新打开：{', '.join(reopened)}"
    newly_completed = [
        task.task_id
        for task in after.tasks
        if not before_by_id[task.task_id].completed and task.completed
    ]
    if newly_completed and newly_completed != [expected_task_id]:
        return f"本轮只能完成 {expected_task_id}，实际新增完成：{', '.join(newly_completed)}"
    return None


def result_is_transient_failure(result: ProcessResult) -> bool:
    if result.timed_out:
        return True
    output = result.output_tail.casefold()
    return any(
        marker in output
        for marker in (
            "rate limit",
            "too many requests",
            "http 429",
            "http 502",
            "http 503",
            "http 504",
            "temporarily unavailable",
            "connection reset",
            "connection aborted",
            "connection timed out",
            "network is unreachable",
            "being used by another process",
            "另一个程序正在使用此文件",
        )
    )


def result_has_retryable_windows_sandbox_failure(result: ProcessResult) -> bool:
    summary = result.retry_summary
    output = "\n".join(
        (
            result.output_tail,
            summary.core_error,
            summary.final_message,
        )
    ).casefold()
    return any(
        marker in output
        for marker in (
            "windows sandbox: helper_unknown_error",
            "windows sandbox failed: helper_unknown_error",
            "setup refresh had errors",
        )
    )


def build_supervisor_sandbox_recovery_request(
    task: PlanTask,
    plan_digest: str,
    result: ProcessResult,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not result_has_retryable_windows_sandbox_failure(result):
        raise ValueError("当前结果不是可恢复的 Windows 沙箱 refresh 失败")
    targets = tuple(
        normalize_project_pattern(path, "allowed_paths") for path in task.allowed_paths
    )
    if not targets or any(any(character in target for character in "*?[") for target in targets):
        raise ValueError("监督器沙箱恢复请求只能使用当前任务的精确 allowed_paths")
    if not task_writable_roots(task):
        raise ValueError("当前任务没有可恢复的源码写入目录")
    failure_detail = next(
        (
            value.strip()
            for value in (
                result.retry_summary.core_error,
                result.retry_summary.final_message,
                result.output_tail,
            )
            if value.strip()
        ),
        "windows sandbox: helper_unknown_error: setup refresh had errors",
    )
    failure_detail = " ".join(failure_detail.split())[:500]
    request = {
        "version": 1,
        "request_id": request_id
        or f"REQ-SANDBOX-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}",
        "kind": SANDBOX_RECOVERY_KIND,
        "task_id": task.task_id,
        "reason": (
            "Codex Windows sandbox refresh 在 worker 命令启动前失败，且 worker 无法写入 "
            "PERMISSION_REQUEST.json；本请求由监督器根据结构化失败自动生成，不代表模型自行授权。"
            f"核心错误：{failure_detail}"
        ),
        "targets": list(targets),
        "risk_level": "medium",
        "risk": (
            "监督器会持久备份并原子重建当前任务最小写入根内由 CodexSandbox 账户拥有的"
            "最外层目录及普通文件；目录树清单或文件哈希不一致时自动回滚"
        ),
        "timeout_seconds": 1800,
        "workspace_root": task.workspace_root,
        "plan_digest": plan_digest,
    }
    return validate_permission_request(request)


def create_supervisor_sandbox_recovery_request(
    task: PlanTask,
    plan: PlanSnapshot,
    result: ProcessResult,
) -> Optional[Dict[str, Any]]:
    if not result_has_retryable_windows_sandbox_failure(result):
        return None
    if PENDING_PERMISSION_FILE.exists() or PENDING_PERMISSION_FILE.is_symlink():
        return None
    state = validate_planning_documents()
    current_plan = parse_plan_file()
    if state.next_task is None or state.next_task.task_id != task.task_id:
        raise RuntimeError("Windows 沙箱恢复请求对应的任务已不是当前任务")
    if current_plan.digest != plan.digest or current_plan.task(task.task_id) != task:
        raise RuntimeError("Windows 沙箱失败后 PLAN.md 已变化，拒绝生成恢复请求")
    request = build_supervisor_sandbox_recovery_request(task, plan.digest, result)
    if PENDING_PERMISSION_FILE.exists() or PENDING_PERMISSION_FILE.is_symlink():
        return None
    atomic_write_json(PENDING_PERMISSION_FILE, request)
    return request


def run_automation(arguments: argparse.Namespace) -> int:
    ensure_runtime_directories()
    codex_executable = resolve_codex_executable()
    codex_version = verify_codex_executable(codex_executable)
    with supervisor_lock():
        cleanup_runtime_temp()
        prepare_previous_round()
        print_color("启动安全无人值守 Codex 生产线……", Colors.CYAN)
        print_color(f"本次使用模型：{arguments.model}；推理力度：{arguments.effort}", Colors.DARK_GRAY)
        print_color(f"Codex CLI：{codex_executable}（{codex_version}）", Colors.DARK_GRAY)
        snapshot = ensure_planning_documents(arguments, codex_executable)
        update_run_state(
            status="RUNNING",
            total_tasks=len(snapshot.tasks),
            completed_tasks=snapshot.completed_count,
            current_task=snapshot.next_task.task_id if snapshot.next_task else None,
        )
        consecutive_failures = 0
        consecutive_no_progress = 0
        update_run_state(consecutive_failures=0, consecutive_no_progress=0, pause_reason=None)
        retry_delay = 5
        previous_result: Optional[ProcessResult] = None
        previous_permission_result: Optional[Dict[str, Any]] = None
        while True:
            snapshot = validate_planning_documents()
            plan = parse_plan_file()
            plan_task = plan.task(snapshot.next_task.task_id) if snapshot.next_task is not None else None
            authorization_context = build_authorization_context(plan_task, plan=plan)
            ensure_authorization(snapshot, authorization_context)
            permission_result = wait_for_permission_resolution(
                snapshot.next_task.task_id if snapshot.next_task is not None else None
            )
            if permission_result is not None:
                previous_permission_result = permission_result
            snapshot = validate_planning_documents()
            plan = parse_plan_file()
            plan_task = plan.task(snapshot.next_task.task_id) if snapshot.next_task is not None else None
            authorization_context = build_authorization_context(plan_task, plan=plan)
            if snapshot.next_task is None:
                ensure_completion_marker(snapshot)
                update_run_state(
                    status="COMPLETED",
                    completed_tasks=len(snapshot.tasks),
                    current_task=None,
                    completed_at=now_iso(),
                )
                print_color("所有任务均已完成，已由监督脚本写入 [ALL_COMPLETED]。", Colors.GREEN)
                return 0
            next_task = snapshot.next_task
            update_run_state(
                status="RUNNING",
                current_task=next_task.task_id,
                current_task_title=next_task.title,
                completed_tasks=snapshot.completed_count,
                total_tasks=len(snapshot.tasks),
            )
            print_color("=" * 60, Colors.YELLOW)
            print_color(f"启动任务 {next_task.task_id}：{next_task.title}", Colors.YELLOW)
            print_color("=" * 60, Colors.YELLOW)
            prompt = worker_prompt(
                plan_task,
                worker_authorization_context(next_task, authorization_context),
                snapshot.completed_count,
                len(snapshot.tasks),
                plan.digest,
                previous_result,
                consecutive_no_progress,
                previous_permission_result,
                agent_instruction_files=authorization_context.files,
            )
            before = snapshot
            state_content_before = STATE_FILE.read_bytes()
            planning_documents_before = {
                path: path.read_bytes() for path in (RULES_FILE, PLAN_FILE)
            }
            protected_control_files_before = {
                path: capture_optional_file_content(path)
                for path in (
                    AUTHORIZATION_FILE,
                    PERMISSION_GRANTS_FILE,
                    RUN_STATE_FILE,
                    SUPERVISOR_METADATA_FILE,
                    APPROVAL_CLAIM_FILE,
                )
            }
            worker_environment = build_worker_environment(next_task.task_id)
            session_workspace = create_session_workspace(
                worker_environment,
                f"task-{next_task.task_id}",
            )
            writable_roots = task_writable_roots(plan_task)
            primary_workspace = task_primary_workspace(plan_task, session_workspace)
            generated_roots = generated_output_roots(plan_task)
            additional_writable_roots = tuple(
                root
                for root in writable_roots
                if root not in generated_roots and not path_is_within(root, primary_workspace)
            )
            guarded_writable_roots = (
                (primary_workspace,) if path_is_within(primary_workspace, SCRIPT_DIR.resolve()) else ()
            ) + additional_writable_roots
            sandbox_metadata_roots = normalized_distinct_roots(
                (WORKER_CONTROL_DIR, *writable_roots)
            )
            cleaned_stale_metadata = cleanup_generated_sandbox_metadata(sandbox_metadata_roots)
            if cleaned_stale_metadata:
                print_color(
                    "已清理上轮残留的 Codex Windows 沙箱元数据："
                    + ", ".join(cleaned_stale_metadata),
                    Colors.DARK_GRAY,
                )
            command = build_codex_command(
                codex_executable,
                arguments.model,
                arguments.effort,
                primary_workspace,
                (WORKER_CONTROL_DIR, *additional_writable_roots),
            )
            workspace_guard: Optional[WorkspaceGuard] = None
            worker_control_guard: Optional[WorkspaceGuard] = None
            acl_backup: Optional[AclBackup] = None
            workspace_violations: Tuple[str, ...] = ()
            workspace_restore_error: Optional[Exception] = None
            temp_cleanup_warning: Optional[OSError] = None
            result: Optional[ProcessResult] = None
            try:
                acl_backup = capture_acl_backup(
                    sandbox_metadata_roots,
                    f"session-{next_task.task_id}",
                )
                workspace_guard = capture_workspace_guard(
                    guarded_writable_roots,
                    task_guard_patterns(plan_task),
                    (AUTOMATION_DIR, *generated_roots),
                )
                worker_control_guard = capture_workspace_guard(
                    (WORKER_CONTROL_DIR,),
                    (
                        project_relative_path(STATE_FILE),
                        project_relative_path(PENDING_PERMISSION_FILE),
                    ),
                )
                result = run_process(
                    command,
                    SCRIPT_DIR,
                    worker_environment,
                    QUIET_TIMEOUT_SECONDS,
                    ABSOLUTE_TIMEOUT_SECONDS,
                    f"task-{next_task.task_id}",
                    render_codex_events=True,
                    stdin_text=prompt,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                print_color(f"Codex 子进程启动或监控失败：{error}", Colors.RED)
            finally:
                try:
                    normalized_owner_paths, _ = normalize_sandbox_owned_paths(
                        existing_task_allowed_files(plan_task),
                        f"session-{next_task.task_id}",
                    )
                    if normalized_owner_paths:
                        print_color(
                            "已归还 worker 新建文件的所有权："
                            + ", ".join(normalized_owner_paths),
                            Colors.DARK_GRAY,
                        )
                except Exception as error:
                    workspace_restore_error = error
                try:
                    restore_acl_backup(acl_backup)
                except Exception as error:
                    if workspace_restore_error is None:
                        workspace_restore_error = error
                try:
                    if worker_control_guard is not None:
                        workspace_violations += restore_workspace_guard(worker_control_guard)
                    if workspace_guard is not None:
                        workspace_violations += restore_workspace_guard(workspace_guard)
                    cleaned_generated_metadata = cleanup_generated_sandbox_metadata(
                        sandbox_metadata_roots
                    )
                    if cleaned_generated_metadata:
                        print_color(
                            "已清理写入目录中的 Codex Windows 沙箱元数据："
                            + ", ".join(cleaned_generated_metadata),
                            Colors.DARK_GRAY,
                        )
                except Exception as error:
                    if workspace_restore_error is None:
                        workspace_restore_error = error
                try:
                    temp_cleanup_warning = remove_owned_temp_path_best_effort(
                        Path(worker_environment["TEMP"]),
                        TEMP_DIR,
                    )
                except Exception as error:
                    if workspace_restore_error is None:
                        workspace_restore_error = error
            if temp_cleanup_warning is not None:
                print_color(
                    "任务临时目录暂时无法清理，将在后续启动时重试："
                    f"{temp_cleanup_warning}",
                    Colors.YELLOW,
                )
            if workspace_restore_error is not None:
                restore_file_content(STATE_FILE, state_content_before)
                reason = f"越界变更恢复失败：{workspace_restore_error}"
                update_run_state(status="PAUSED_INVALID_STATE", pause_reason=reason)
                print_color(reason, Colors.RED)
                return 3
            if workspace_violations:
                restore_file_content(STATE_FILE, state_content_before)
                reason = (
                    "工作会话修改了 allowed_paths 之外的文件，已恢复："
                    + ", ".join(workspace_violations[:20])
                )
                if len(workspace_violations) > 20:
                    reason += f" 等 {len(workspace_violations)} 项"
                update_run_state(status="PAUSED_SCOPE_VIOLATION", pause_reason=reason)
                print_color(reason, Colors.RED)
                return 3
            changed_planning_documents = [
                path
                for path, content in planning_documents_before.items()
                if not path.is_file() or path.read_bytes() != content
            ]
            if changed_planning_documents:
                for path, content in planning_documents_before.items():
                    restore_file_content(path, content)
                restore_file_content(STATE_FILE, state_content_before)
                changed_names = ", ".join(path.name for path in changed_planning_documents)
                reason = f"工作会话修改了只能由规划阶段维护的文档：{changed_names}"
                update_run_state(status="PAUSED_INVALID_STATE", pause_reason=reason)
                print_color(f"检测到规划文档异常，已恢复并暂停：{reason}", Colors.RED)
                return 3
            changed_control_files = [
                path
                for path, content in protected_control_files_before.items()
                if optional_file_changed(path, content)
            ]
            if changed_control_files:
                for path, content in protected_control_files_before.items():
                    restore_optional_file_content(path, content)
                restore_file_content(STATE_FILE, state_content_before)
                changed_names = ", ".join(path.name for path in changed_control_files)
                reason = f"工作会话修改了只能由监督脚本维护的控制文件，已恢复：{changed_names}"
                update_run_state(status="PAUSED_INVALID_STATE", pause_reason=reason)
                print_color(reason, Colors.RED)
                return 3
            if result is not None and previous_permission_result is not None:
                consume_permission_result(previous_permission_result)
                previous_permission_result = None
            retryable_sandbox_failure = (
                result is not None and result_has_retryable_windows_sandbox_failure(result)
            )
            if retryable_sandbox_failure and result is not None:
                recovery_request = create_supervisor_sandbox_recovery_request(
                    plan_task,
                    plan,
                    result,
                )
                if recovery_request is not None:
                    print_color(
                        "Worker 无法写入控制文件，监督器已根据结构化沙箱失败生成恢复请求："
                        f"{recovery_request['request_id']}",
                        Colors.YELLOW,
                    )
            if PENDING_PERMISSION_FILE.exists():
                if restore_file_content(STATE_FILE, state_content_before):
                    print_color("权限请求产生时任务状态发生变化，已恢复原状态。", Colors.YELLOW)
                consecutive_failures = 0
                retry_delay = 5
                previous_result = result
                update_run_state(consecutive_failures=0)
                continue
            process_succeeded = (
                result is not None
                and result.return_code == 0
                and not retryable_sandbox_failure
            )
            if process_succeeded:
                expected_state_content = state_content_after_task_completion(
                    state_content_before.decode("utf-8"),
                    next_task.task_id,
                ).encode("utf-8")
                current_state_content = STATE_FILE.read_bytes() if STATE_FILE.is_file() else b""
                if current_state_content not in {state_content_before, expected_state_content}:
                    restore_file_content(STATE_FILE, state_content_before)
                    reason = "工作会话对 STATE.md 做了当前任务复选框之外的修改"
                    update_run_state(status="PAUSED_INVALID_STATE", pause_reason=reason)
                    print_color(f"检测到非法状态修改，已恢复并暂停：{reason}", Colors.RED)
                    return 3
            elif restore_file_content(STATE_FILE, state_content_before):
                print_color("工作会话未成功退出，已恢复本轮任务状态。", Colors.YELLOW)
            try:
                after = validate_planning_documents()
            except (OSError, ValueError) as error:
                update_run_state(status="PAUSED_INVALID_STATE", pause_reason=str(error))
                print_color(f"状态文件校验失败，已暂停：{error}", Colors.RED)
                return 3
            transition_error = state_transition_error(before, after, next_task.task_id)
            if transition_error:
                update_run_state(status="PAUSED_INVALID_STATE", pause_reason=transition_error)
                print_color(f"检测到非法状态迁移，已暂停：{transition_error}", Colors.RED)
                return 3
            progressed = after.completed_count > before.completed_count
            if process_succeeded and progressed:
                consecutive_failures = 0
                consecutive_no_progress = 0
                retry_delay = 5
                previous_result = None
                previous_permission_result = None
                update_run_state(
                    consecutive_failures=0,
                    consecutive_no_progress=0,
                    last_success_at=now_iso(),
                    last_log=str(result.log_file.relative_to(SCRIPT_DIR)),
                )
                print_color(
                    f"任务进度已更新：{after.completed_count}/{len(after.tasks)}，准备下一轮。",
                    Colors.GREEN,
                )
                continue
            if result is not None:
                startup_error = deterministic_codex_startup_error(result)
                if startup_error:
                    log_path = str(result.log_file.relative_to(SCRIPT_DIR))
                    reason = f"{startup_error}；日志：{log_path}"
                    update_run_state(
                        status="PAUSED_STARTUP_ERROR",
                        pause_reason=reason,
                        last_failure=reason,
                        last_log=log_path,
                    )
                    print_color(reason, Colors.RED)
                    print_color("重试该错误不会恢复，监督脚本已立即暂停。", Colors.YELLOW)
                    return 6
            if retryable_sandbox_failure:
                consecutive_failures += 1
                consecutive_no_progress = 0
                reason = (
                    "Windows 沙箱 refresh 失败"
                    f"（连续基础设施失败 {consecutive_failures} 次）"
                )
            elif result is not None and result.return_code == 0:
                consecutive_no_progress += 1
                consecutive_failures = 0
                reason = f"会话成功退出，但 STATE.md 未新增已完成任务（连续 {consecutive_no_progress} 次）"
            else:
                consecutive_failures += 1
                reason = (
                    f"Codex 会话失败（连续 {consecutive_failures} 次）"
                    if result is None
                    else f"Codex 退出码 {result.return_code}（连续失败 {consecutive_failures} 次）"
                )
                if result is not None and result.timed_out:
                    reason = f"{reason}；{result.timeout_reason}"
            update_run_state(
                consecutive_failures=consecutive_failures,
                consecutive_no_progress=consecutive_no_progress,
                last_failure=reason,
                last_log=str(result.log_file.relative_to(SCRIPT_DIR)) if result else None,
            )
            print_color(reason, Colors.RED)
            if consecutive_no_progress >= MAX_NO_PROGRESS:
                update_run_state(status="PAUSED_NO_PROGRESS", pause_reason=reason)
                print_color("连续无进展次数达到上限，已暂停以避免持续消耗额度。", Colors.RED)
                print_color(f"检查原因后直接重新运行 python {SCRIPT_NAME} 即可续跑。", Colors.YELLOW)
                return 4
            if retryable_sandbox_failure and consecutive_failures >= MAX_WINDOWS_SANDBOX_FAILURES:
                update_run_state(status="PAUSED_WINDOWS_SANDBOX", pause_reason=reason)
                print_color(
                    "Windows 沙箱连续 refresh 失败，已暂停，避免用相同写入根重复消耗模型额度。",
                    Colors.RED,
                )
                print_color(
                    "重新运行时监督器会先清理生成目录中的残留沙箱元数据，再创建新会话。",
                    Colors.YELLOW,
                )
                return 5
            if process_succeeded:
                previous_result = result
                print_color("立即使用结构化上下文纠正续做。", Colors.DARK_GRAY)
                continue
            transient_failure = (
                retryable_sandbox_failure
                or result is None
                or result_is_transient_failure(result)
            )
            if not transient_failure:
                update_run_state(status="PAUSED_FAILURES", pause_reason=reason)
                print_color("该失败不属于可安全重试的瞬时错误，已立即暂停。", Colors.RED)
                return 5
            if consecutive_failures >= MAX_TRANSIENT_FAILURES:
                update_run_state(status="PAUSED_FAILURES", pause_reason=reason)
                print_color("连续失败次数达到上限，已暂停以避免无限重试。", Colors.RED)
                print_color(f"检查日志后直接重新运行 python {SCRIPT_NAME} 即可续跑。", Colors.YELLOW)
                return 5
            previous_result = result
            print_color(f"等待 {retry_delay} 秒后重试……", Colors.DARK_GRAY)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 300)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="安全、可恢复的 Codex 无人值守监督脚本")
    parser.add_argument("--model", default="gpt-5.6-terra", help="选择 Codex 模型")
    parser.add_argument(
        "--effort",
        choices=("low", "medium", "high", "xhigh"),
        default="high",
        help="覆盖内置模型推理力度",
    )
    subparsers = parser.add_subparsers(dest="action")
    subparsers.add_parser("status", help="显示运行状态")
    subparsers.add_parser("help", help="显示详细中文使用说明")
    parser.set_defaults(action="run")
    return parser


def main() -> int:
    if os.name == "nt":
        os.system("")
    parser = build_argument_parser()
    arguments = parser.parse_args(sys.argv[1:])
    try:
        if arguments.action == "run":
            ensure_gitignore_rules()
            return run_automation(arguments)
        if arguments.action == "status":
            return show_status()
        if arguments.action == "help":
            return show_usage_help()
        parser.error("未知操作")
    except KeyboardInterrupt:
        print_color("收到键盘中断，监督脚本已停止。", Colors.YELLOW)
        return 130
    except InteractiveInputUnavailableError as error:
        waiting_for_approval = PENDING_PERMISSION_FILE.is_file()
        update_run_state(
            status="WAITING_APPROVAL" if waiting_for_approval else "PAUSED_INPUT_REQUIRED",
            pause_reason=str(error),
        )
        print_color(str(error), Colors.YELLOW)
        return 8
    except AuthorizationDeniedError as error:
        print_color(f"自动化已暂停：{error}", Colors.YELLOW)
        return 7
    except Exception as error:
        try:
            update_run_state(status="FAILED", pause_reason=str(error))
        except Exception:
            pass
        print_color(f"错误：{error}", Colors.RED)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
