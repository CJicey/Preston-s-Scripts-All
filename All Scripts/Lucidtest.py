import os
import re
import time
import shutil
import logging
import subprocess
from datetime import datetime
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---- Optional COM shortcut creation (preferred if available) ----
try:
    import pythoncom  # type: ignore
    from win32com.client import Dispatch  # type: ignore
    HAVE_PYWIN32 = True
except Exception:
    HAVE_PYWIN32 = False

# =========================
# Configuration (portable)
# =========================
YEAR = os.getenv("BPL_YEAR", str(datetime.now().year))

# Prefer UNC if you have it; otherwise provide drive letters. You can set any of these via ENV.
EGNYTE_ROOT = os.getenv("EGNYTE_ROOT_UNC") or os.getenv("EGNYTE_ROOT_DRIVE") or r"Z:\Shared\Projects"
LUCID_ROOT  = os.getenv("LUCID_ROOT_UNC")  or os.getenv("LUCID_ROOT_DRIVE")  or r"L:\Revit\2_PROJECTS"

# Template project used to seed new LucidLink projects
TEMPLATE_FOLDER = os.getenv(
    "LUCID_TEMPLATE_FOLDER",
    rf"{LUCID_ROOT}\{int(YEAR)}\{YEAR[2:]}.08.000 - Raleigh\{YEAR[2:]}.08.### - Arch name - Project name"
)

# General Notes source
GEN_NOTES_SOURCE = os.getenv(
    "GEN_NOTES_SOURCE",
    r"L:\Revit\1_BP_REVIT\BP_REVIT GENERAL NOTES\GEN NOTES - EXCEL"
)

# City map: “city folder name on Egnyte” -> “Lucid destination folder”
CITY_MAP = {
    f"{YEAR[2:]}.00.000 - Atlanta":   rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.00.000 - Atlanta",
    f"{YEAR[2:]}.01.000 - Corporate - Admin": rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.01.000 - Corporate - Admin",
    f"{YEAR[2:]}.02.000 - Nashville": rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.02.000 - Nashville",
    f"{YEAR[2:]}.03.000 - Florida":   rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.03.000 - Florida",
    f"{YEAR[2:]}.04.000 - Knoxville": rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.04.000 - Knoxville",
    f"{YEAR[2:]}.05.000 - Chattanooga": rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.05.000 - Chattanooga",
    f"{YEAR[2:]}.06.000 - Sarasota":  rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.06.000 - Sarasota",
    f"{YEAR[2:]}.07.000 - Charlotte": rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.07.000 - Charlotte",
    f"{YEAR[2:]}.08.000 - Raleigh":   rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.08.000 - Raleigh",
    f"{YEAR[2:]}.09.000 - Loudoun":   rf"{LUCID_ROOT}\{YEAR}\{YEAR[2:]}.09.000 - Loudoun",
}

# Project folder name pattern (configurable)
PROJECT_NAME_REGEX = os.getenv("PROJECT_NAME_REGEX", r'\d{2}\.\d{2}\.\d{3} - .+')

# Logging location (ProgramData is safer cross-desktop)
DEFAULT_LOG_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                               "BPL", "LucidEgnyteLNK")
LOG_DIR = os.getenv("LOG_DIR", DEFAULT_LOG_DIR)
LOG_FILE = os.path.join(LOG_DIR, "LucidEgnyteLnk.log")

# Poll interval (seconds)
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SEC", "300"))

# =========================
# Utilities
# =========================
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def normalize(path: str) -> str:
    return path.replace("/", "\\")

def safe_join(*parts) -> str:
    return normalize(os.path.join(*parts))

def path_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False

def egnyte_city_root(city_folder_name: str) -> str:
    return safe_join(EGNYTE_ROOT, YEAR, city_folder_name)

def create_shortcut_ps(target_path: str, link_path: str):
    # PowerShell fallback for creating .lnk
    target = normalize(target_path)
    link   = normalize(link_path)

    # Robust PS with explicit powershell.exe and careful quoting
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{link}');"
        "$s.TargetPath='{target}';"
        "$s.WorkingDirectory='{work}';"
        "$s.Save();"
    ).format(link=link.replace("'", "''"),
             target=target.replace("'", "''"),
             work=os.path.dirname(target).replace("'", "''"))

    cmd = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps]
    subprocess.run(cmd, check=True)

def create_shortcut(target_path: str, link_path: str, logger: logging.Logger):
    ensure_dir(os.path.dirname(link_path))
    try:
        if HAVE_PYWIN32:
            pythoncom.CoInitialize()
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortcut(link_path)
            shortcut.TargetPath = target_path
            shortcut.WorkingDirectory = os.path.dirname(target_path)
            shortcut.Save()
            logger.info(f"Shortcut (COM) created: {link_path}")
            return
    except Exception as e:
        logger.warning(f"COM shortcut creation failed, falling back to PowerShell. Error: {e}")

    # Fallback to PowerShell
    try:
        create_shortcut_ps(target_path, link_path)
        logger.info(f"Shortcut (PowerShell) created: {link_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create shortcut via PowerShell: {e}")
        raise

# =========================
# Core logic
# =========================
class CityFolderHandler(FileSystemEventHandler):
    def __init__(self, city_map, processed_set, logger):
        self.city_map = city_map
        self.processed = processed_set   # shared set across watchers + poller
        self.logger = logger
        self.pattern = re.compile(PROJECT_NAME_REGEX)

    def on_created(self, event):
        try:
            if not event.is_directory:
                return

            new_folder_path = normalize(event.src_path)
            folder_name = os.path.basename(new_folder_path)

            if new_folder_path in self.processed:
                return

            self.logger.info(f"Folder created: {new_folder_path}")

            if not self.pattern.match(folder_name):
                # Not a project folder we care about
                return

            # Determine which city this belongs to by checking the path
            for city_code, lucid_folder in self.city_map.items():
                if city_code in new_folder_path:
                    lucid_project_folder = safe_join(lucid_folder, folder_name)

                    # Copy template structure if destination doesn't exist
                    if not path_exists(lucid_project_folder):
                        self.logger.info(f"Creating LucidLink folder: {lucid_project_folder}")
                        try:
                            shutil.copytree(TEMPLATE_FOLDER, lucid_project_folder)
                        except FileExistsError:
                            self.logger.warning("Template copy skipped; destination already exists.")
                        except Exception as e:
                            self.logger.error(f"Error copying template: {e}")

                        # Copy General Notes
                        gen_notes_dest = safe_join(lucid_project_folder, "4_General Notes")
                        if path_exists(GEN_NOTES_SOURCE) and path_exists(gen_notes_dest):
                            try:
                                for item in os.listdir(GEN_NOTES_SOURCE):
                                    s = safe_join(GEN_NOTES_SOURCE, item)
                                    d = safe_join(gen_notes_dest, item)
                                    if os.path.isdir(s):
                                        shutil.copytree(s, d, dirs_exist_ok=True)
                                    else:
                                        ensure_dir(os.path.dirname(d))
                                        shutil.copy2(s, d)
                                self.logger.info(f"Copied General Notes to: {gen_notes_dest}")
                            except Exception as e:
                                self.logger.error(f"Error copying General Notes: {e}")
                        else:
                            self.logger.warning(
                                f"Missing Notes source or destination. Source exists? {path_exists(GEN_NOTES_SOURCE)} "
                                f"Dest exists? {path_exists(gen_notes_dest)}"
                            )

                        # Shortcuts both ways
                        try:
                            create_shortcut(new_folder_path,
                                            safe_join(lucid_project_folder, f"{folder_name}.lnk"),
                                            self.logger)
                            create_shortcut(lucid_project_folder,
                                            safe_join(new_folder_path, f"{folder_name}.lnk"),
                                            self.logger)
                        except Exception:
                            # Already logged
                            pass

                    # Mark processed after attempting actions
                    self.processed.add(new_folder_path)
                    break

        except Exception as e:
            self.logger.error("Unhandled exception in on_created", exc_info=True)

def get_existing_project_folders(city_map, logger):
    existing = set()
    for city_folder_name in city_map.keys():
        egnyte_folder = egnyte_city_root(city_folder_name)
        if path_exists(egnyte_folder):
            try:
                for item in os.listdir(egnyte_folder):
                    p = safe_join(egnyte_folder, item)
                    if os.path.isdir(p):
                        existing.add(p)
            except Exception as e:
                logger.warning(f"Cannot list {egnyte_folder}: {e}")
        else:
            logger.warning(f"Egnyte city folder missing: {egnyte_folder}")
    return existing

def poll_folders(city_map, handler: CityFolderHandler, processed_set: set, logger: logging.Logger):
    while True:
        try:
            logger.info("Polling cycle...")
            for city_folder_name in city_map.keys():
                egnyte_folder = egnyte_city_root(city_folder_name)
                if not path_exists(egnyte_folder):
                    continue
                try:
                    for item in os.listdir(egnyte_folder):
                        p = safe_join(egnyte_folder, item)
                        if os.path.isdir(p) and p not in processed_set:
                            logger.info(f"Polling detected new folder: {p}")
                            # Simulate event
                            event = type('Event', (), {'is_directory': True, 'src_path': p})()
                            handler.on_created(event)
                            processed_set.add(p)
                except Exception as e:
                    logger.warning(f"Cannot list during poll {egnyte_folder}: {e}")
            logger.info("Polling complete.")
        except Exception:
            logger.error("Error in poll loop", exc_info=True)

        time.sleep(POLL_INTERVAL)

def wait_for_paths(logger: logging.Logger, max_wait=600, check_interval=10):
    """Wait for either UNC roots or mapped drives to exist."""
    logger.info("Waiting for Egnyte and Lucid roots...")
    start = time.time()

    def roots_ready():
        eg_ok = path_exists(EGNYTE_ROOT)
        lu_ok = path_exists(LUCID_ROOT)
        return eg_ok and lu_ok

    while time.time() - start < max_wait:
        if roots_ready():
            logger.info("Roots available.")
            return True
        time.sleep(check_interval)

    logger.error("Timeout: Egnyte and/or Lucid roots not available.")
    return False

# =========================
# Entrypoint
# =========================
if __name__ == "__main__":
    ensure_dir(LOG_DIR)

    logger = logging.getLogger("LucidEgnyteLNK")
    logger.setLevel(logging.INFO)

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    ch = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info("Starting portable folder monitor...")

    if not wait_for_paths(logger):
        # Don’t crash—keep running; admins can see the log
        pass

    # Shared processed set for ALL handlers + poller
    processed = get_existing_project_folders(CITY_MAP, logger)
    logger.info(f"Seeded processed set with {len(processed)} existing folders.")

    observers = []
    handler = CityFolderHandler(CITY_MAP, processed, logger)

    # Start one observer per city root (non-recursive)
    for city_folder_name in CITY_MAP.keys():
        egnyte_folder = egnyte_city_root(city_folder_name)
        if path_exists(egnyte_folder):
            try:
                obs = Observer()
                obs.schedule(handler, path=egnyte_folder, recursive=False)
                obs.start()
                observers.append(obs)
                logger.info(f"Watching: {egnyte_folder}")
            except Exception as e:
                logger.error(f"Failed to start observer for {egnyte_folder}: {e}")
        else:
            logger.warning(f"Skipping missing city folder: {egnyte_folder}")

    # Start poller (daemon)
    if observers:
        t = Thread(target=poll_folders, args=(CITY_MAP, handler, processed, logger), daemon=True)
        t.start()
    else:
        logger.warning("No observers started; poller will still attempt periodic scans.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()
        logger.info("Shutdown complete.")
