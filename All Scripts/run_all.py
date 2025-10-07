import datetime as dt
import sys
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Tuple, Optional

# ---------------------------------------------
# Configuration & paths
# ---------------------------------------------

PY = sys.executable  # use the same interpreter as the runner (works in venvs)

SCRIPTS = [
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\Projects.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\MasterProposals.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\Azure-Signin-Monitor.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\MasterProjects.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\RegularMasterProposals.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\MasterOpportunity.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\LucidEgnyteLnk.py",
    r"C:\Users\CalebJohnson\Desktop\All Scripts\Scripts\scantoz_watcher.py",
]

ROOT = Path(__file__).parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

RUN_TS = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
MASTER_LOG = LOG_DIR / f"run_{RUN_TS}.log"

HEARTBEAT_SEC = 10  # how often to print a status heartbeat


# ---------------------------------------------
# Helpers
# ---------------------------------------------

def fmt_dur(sec: float) -> str:
    if sec < 0:
        sec = 0
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h:d}h {m:02d}m {s:02d}s"
    if m:
        return f"{m:d}m {s:02d}s"
    return f"{s:d}s"


def append_log(line: str, also_print: bool = True) -> None:
    stamp = f"[{dt.datetime.now().isoformat(timespec='seconds')}] {line}"
    with MASTER_LOG.open("a", encoding="utf-8") as f:
        f.write(stamp + "\n")
    if also_print:
        print(stamp)


def _pump_output(proc: subprocess.Popen, tf, prefix: str) -> None:
    """
    Tee child stdout-> console + per-script log, prefixing each line with the script name.
    """
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        msg = f"{prefix} | {line}\n"
        sys.stdout.write(msg)
        tf.write(line + "\n")
        tf.flush()
        sys.stdout.flush()


# ---------------------------------------------
# Parallel runner
# ---------------------------------------------

class Child:
    def __init__(self, path: Path, log_path: Path):
        self.path = path
        self.name = path.name
        self.log_path = log_path
        self.proc: Optional[subprocess.Popen] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.returncode: Optional[int] = None
        self._pump_thread: Optional[threading.Thread] = None
        self._log_file_handle = None

    def start(self):
        # Log start
        append_log(f"START: {self.name}  (cwd={self.path.parent})")

        self._log_file_handle = self.log_path.open("w", encoding="utf-8")
        self.start_time = time.time()
        self.proc = subprocess.Popen(
            [PY, str(self.path)],
            cwd=str(self.path.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        prefix = f"[{self.name[:30]:30}]"
        self._pump_thread = threading.Thread(
            target=_pump_output,
            args=(self.proc, self._log_file_handle, prefix),
            daemon=True
        )
        self._pump_thread.start()

    def poll(self):
        if self.proc is None:
            return None
        return self.proc.poll()

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = time.time() if self.end_time is None else self.end_time
        return end - self.start_time

    def finalize(self):
        if self.proc is not None:
            self.returncode = self.proc.poll()
        self.end_time = time.time()
        if self._pump_thread is not None:
            self._pump_thread.join(timeout=2)
        if self._log_file_handle is not None:
            try:
                self._log_file_handle.flush()
                self._log_file_handle.close()
            except Exception:
                pass
        status = "OK" if (self.returncode == 0) else f"FAIL({self.returncode})"
        append_log(f"END: {self.name} -> {status} in {fmt_dur(self.duration())}  (log: {self.log_path})")

    def terminate(self):
        try:
            if self.proc and self.is_running():
                self.proc.terminate()
        except Exception:
            pass

    def kill(self):
        try:
            if self.proc and self.is_running():
                self.proc.kill()
        except Exception:
            pass


def print_summary(children: List[Child]) -> None:
    print("\n\nSummary:")
    print("-" * 78)
    print(f"{'Script':55}  {'Status':8}  {'Duration':9}  Log")
    print("-" * 78)
    for c in children:
        rc = c.returncode if c.returncode is not None else (0 if c.is_running() else -1)
        status = ("RUNNING" if c.is_running()
                  else ("OK" if rc == 0 else f"FAIL({rc})"))
        print(f"{c.name[:55]:55}  {status:8}  {fmt_dur(c.duration()):9}  {c.log_path}")
    print("-" * 78)


def main():
    append_log(f"=== RUN (PARALLEL) START {RUN_TS} ===")

    # Build child objects; skip missing files but log it
    children: List[Child] = []
    for spath in SCRIPTS:
        p = Path(spath)
        if not p.exists():
            append_log(f"ERROR: Not found -> {spath}")
            continue
        log_path = LOG_DIR / f"{RUN_TS}_{p.name.replace(' ', '_')}.log"
        children.append(Child(p, log_path))

    # Start all children at once
    for c in children:
        c.start()
        time.sleep(0.05)  # small stagger to keep console readable

    start_all = time.time()
    last_heartbeat = 0.0

    try:
        # Stay alive while any child is running (good for long-running watchers)
        while any(c.is_running() for c in children):
            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_SEC:
                last_heartbeat = now
                running = [c for c in children if c.is_running()]
                done_ok = [c for c in children if (not c.is_running() and (c.returncode == 0 if c.returncode is not None else False))]
                done_fail = [c for c in children if (not c.is_running() and (c.returncode not in (None, 0)))]
                append_log(
                    f"HB: running={len(running)} ok={len(done_ok)} fail={len(done_fail)} "
                    f"| up {fmt_dur(now - start_all)}",
                    also_print=True
                )
            # Finalize any that have just finished
            for c in children:
                if (not c.is_running()) and (c.end_time is None) and (c.proc is not None):
                    c.finalize()

            time.sleep(0.25)

    except KeyboardInterrupt:
        append_log("KeyboardInterrupt: terminating all children...", also_print=True)
        for c in children:
            c.terminate()
        # give them a moment to shut down cleanly
        time.sleep(2)
        for c in children:
            if c.is_running():
                c.kill()

    # Finalize any stragglers
    for c in children:
        if c.end_time is None:
            c.finalize()

    append_log(f"=== RUN (PARALLEL) END {RUN_TS} | up {fmt_dur(time.time() - start_all)} ===")

    print_summary(children)

    # Exit nonzero if any failed
    failures = sum(1 for c in children if (c.returncode not in (None, 0)))
    print(f"\nTotal up time: {fmt_dur(time.time() - start_all)} | Failures: {failures}")

    # Keep window open if interactive
    try:
        if sys.stdin.isatty():
            input("\n--- Press Enter to close ---")
    except Exception:
        pass

    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
