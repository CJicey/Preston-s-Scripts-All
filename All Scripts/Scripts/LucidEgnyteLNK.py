import time
import os
import shutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import re
from threading import Thread

# ---------------------------
# File watcher + poller workflow
# ---------------------------
# This script watches multiple "city" project folders on Z:\ (Egnyte) for newly
# created project subfolders (e.g., "25.08.123 - Arch name - Project name").
# When a new project folder appears, it mirrors a template folder into the
# corresponding LucidLink L:\ structure, copies "General Notes" content,
# and creates .lnk shortcuts in both directions (Egnyte <-> Lucid).
#
# There are two detection mechanisms:
#   1) Real-time: Watchdog Observer triggers on_created when a new directory is made.
#   2) Polling: A background thread periodically scans and simulates creation events.
#
# processed_folders keeps track of already-handled folders so work isn't duplicated.


class CityFolderHandler(FileSystemEventHandler):
    """
    Watchdog handler for directory creation events in a city folder.
    Uses a local set to prevent reprocessing the same folder twice.
    """
    def __init__(self, city_map):
        # city_map maps a city code/name to its LucidLink destination base folder
        self.city_map = city_map
        # Tracks Egnyte project folder paths that we've already processed
        self.processed_folders = set()

    def on_created(self, event):
        """
        Triggered by Watchdog when a file/directory is created in a monitored path.
        We only care about directories that match the project naming convention.
        """
        ## ADDED ERROR HANDLING
        try:
            if event.is_directory:
                new_folder_path = event.src_path  # Full path to the newly created dir
                folder_name = os.path.basename(new_folder_path)  # Just the last segment

                # Skip if we already handled this exact path (guards against dupes
                # from both the event and the polling thread).
                if new_folder_path in self.processed_folders:
                    return

                self.processed_folders.add(new_folder_path)
                logging.info(f"Folder created: {new_folder_path}")

                # Only proceed if the folder name matches "NN.NN.NNN - something"
                # Example: "25.08.123 - Arch name - Project name"
                if re.match(r'\d{2}\.\d{2}\.\d{3} - .+', folder_name):
                    # Determine which top-level city this belongs to
                    # by checking the full new path for a city code key.
                    for city_code, lucid_folder in self.city_map.items():
                        if city_code in new_folder_path:
                            logging.info(f"Detected creation in city folder: {city_code}")

                            # Destination project path in LucidLink
                            lucid_project_folder = os.path.join(lucid_folder, folder_name)

                            # Only copy the template if the Lucid destination doesn't exist yet
                            if not os.path.exists(lucid_project_folder):
                                logging.info(f"Creating LucidLink folder: {lucid_project_folder}")

                                # Source template to copy into new project folder
                                template_folder = "L:/Revit/2_PROJECTS/2024/24.08.000 - Raleigh/24.08.### - Arch name - Project name"
                                try:
                                    # Recursively copy template folder structure
                                    shutil.copytree(template_folder, lucid_project_folder)
                                except FileExistsError as fe:
                                    # It might have been created moments ago by another process or the poller
                                    logging.warning(f"Template folder copy skipped; already exists: {fe}")
                                except Exception as e:
                                    # Catch-all for unexpected copy errors (permissions, locks, etc.)
                                    logging.error(f"Unexpected error while copying template folder: {e}")

                                # Copy "GEN NOTES - EXCEL" contents into the project's "4_General Notes"
                                gen_notes_source = r"L:\Revit\1_BP_REVIT\BP_REVIT GENERAL NOTES\GEN NOTES - EXCEL"
                                gen_notes_dest = os.path.join(lucid_project_folder, "4_General Notes")

                                if os.path.exists(gen_notes_source) and os.path.exists(gen_notes_dest):
                                    for item in os.listdir(gen_notes_source):
                                        s = os.path.join(gen_notes_source, item)
                                        d = os.path.join(gen_notes_dest, item)
                                        if os.path.isdir(s):
                                            shutil.copytree(s, d)  # Copy subfolder recursively
                                        else:
                                            shutil.copy2(s, d)     # Copy single file with metadata
                                    logging.info(f"Copied General Notes to: {gen_notes_dest}")
                                else:
                                    logging.warning(
                                        f"Either source {gen_notes_source} or destination {gen_notes_dest} does not exist."
                                    )

                                # Create Windows .lnk shortcuts in both directions:
                                #   Egnyte -> Lucid, and Lucid -> Egnyte
                                create_shortcut(new_folder_path, os.path.join(lucid_project_folder, f"{folder_name}.lnk"))
                                create_shortcut(lucid_project_folder, os.path.join(new_folder_path, f"{folder_name}.lnk"))
                                logging.info(f"Shortcuts created for {new_folder_path} and {lucid_project_folder}")
                            break
        except Exception as e:  # Broad catch so the thread won't die if something unexpected occurs
            logging.error(f"Unhandled exception in on_created: {e}", exc_info=True)


def create_shortcut(target_path, link_path):
    """
    Creates a Windows .lnk shortcut using PowerShell and the WScript.Shell COM object.
    - target_path: the folder the shortcut should point to
    - link_path: the .lnk file to create
    """
    # Normalize paths to backslashes to avoid quoting/escaping issues in PowerShell
    target_path = target_path.replace('/', '\\')
    link_path = link_path.replace('/', '\\')

    # PowerShell snippet:
    # 1) Create the shortcut object
    # 2) Set its TargetPath
    # 3) Save it
    # 4) Mark its attributes (Archive, ReparsePoint) to help Windows treat it like a link
    command = (
        f'powershell -command "$s=(New-Object -COM WScript.Shell).CreateShortcut(\'{link_path}\');'
        f'$s.TargetPath=\'{target_path}\';$s.Save();'
        f'(Get-Item \'{link_path}\').Attributes = \'Archive,ReparsePoint\'"'
    )

    try:
        # shell=True to run the PS command string; check=True raises if non-zero exit code
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Shortcut created successfully: {link_path}")
    except subprocess.CalledProcessError as e:
        # Log and re-raise to allow caller to decide whether to continue
        logging.error(f"Failed to create shortcut {link_path}. Error: {e}")
        raise


def get_existing_folders(city_map):
    """
    Scans the Egnyte city folders for already existing project subfolders and returns a set of paths.
    This is used to seed 'processed_folders' so those don't get reprocessed at startup.
    """
    existing_folders = set()
    for folder_name, _ in city_map.items():
        egnyte_folder = f"Z:/Shared/Projects/2025/{folder_name}"
        if os.path.exists(egnyte_folder):
            for item in os.listdir(egnyte_folder):
                item_path = os.path.join(egnyte_folder, item)
                if os.path.isdir(item_path):
                    existing_folders.add(item_path)
    return existing_folders


def poll_folders(city_map, handler, processed_folders):
    """
    Background polling loop (daemon thread).
    Periodically scans each Egnyte city folder to find any new subfolders that might have been
    missed by real-time events (e.g., network hiccups or external tools creating folders quietly).
    For any unseen folder, it simulates a Watchdog 'on_created' event to reuse the same logic.
    """
    while True:
        ## ADDED ERROR HANDLING
        try:
            logging.info("Starting folder polling...")
            for folder_name, lucid_folder in city_map.items():
                egnyte_folder = f"Z:/Shared/Projects/2025/{folder_name}"
                if os.path.exists(egnyte_folder):
                    for item in os.listdir(egnyte_folder):
                        item_path = os.path.join(egnyte_folder, item)
                        # Only consider directories that haven't been processed yet
                        if os.path.isdir(item_path) and item_path not in processed_folders:
                            logging.info(f"Polling detected new folder: {item_path}")
                            # Construct a lightweight object that mimics the Watchdog event
                            event = type('Event', (), {'is_directory': True, 'src_path': item_path})()
                            handler.on_created(event)            # Reuse the on_created logic
                            processed_folders.add(item_path)     # Mark as handled to avoid repeats
            logging.info("Folder polling completed. Waiting for next cycle...")
        except Exception as e:
            # Never die on exception; log and continue next loop
            logging.error(f"Error in poll_folders loop: {e}", exc_info=True)

        time.sleep(300)  # Sleep 5 minutes between scans to reduce load


def wait_for_drives(max_wait_time=600):  # 600 seconds = 10 minutes
    """
    Blocks until L:\ and Z:\ are available (or until max_wait_time is exceeded).
    Useful at service start to wait for network/mapped drives to mount.
    Returns True if both are found in time, else False.
    """
    logger.info(r"Waiting for L:\ and Z:\ drives to become available...")
    start_time = time.time()
    while time.time() - start_time < max_wait_time:
        if os.path.exists(r"L:\\") and os.path.exists(r"Z:\\"):
            logger.info(r"Both L:\ and Z:\ drives are now available.")
            return True
        time.sleep(10)  # Check every 10 seconds

    logger.error(r"Timeout: L:\ and/or Z:\ drives did not become available within 10 minutes.")
    return False


if __name__ == "__main__":
    # ---------------------------
    # Logging setup
    # ---------------------------
    log_dir = r"C:\Scripts\LucidEgnyteLNK\v3 - Triggers on Creation with Polling"
    log_file = os.path.join(log_dir, "LucidEgnyteLnk.log")

    # Root logger handles both file + console
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # File handler (persistent logs)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    # Console handler (visible in stdout)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Consistent log format with timestamps + levels
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Attach handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("Starting the folder monitoring script...")

    # Ensure required drives are mounted before watching/copying
    if not wait_for_drives():
        # NOTE: This line looks like a leftover typo; it won’t log anything as-is.
        # Keeping it unchanged per instructions, but in practice you'd call logger.error(...)
        logger.e  # (Preserved as in original script, though likely a typo)

    # ---------------------------
    # City folders to monitor (Egnyte Z:\) and their LucidLink destinations (L:\)
    # Keys must match a segment expected to appear in the new folder's path so detection works.
    # ---------------------------
    city_map = {
        "25.00.000 - Atlanta": "L:/Revit/2_PROJECTS/2025/25.00.000 - Atlanta",
        "25.01.000 - Corporate - Admin": "L:/Revit/2_PROJECTS/2025/25.01.000 - Corporate - Admin",
        "25.02.000 - Nashville": "L:/Revit/2_PROJECTS/2025/25.02.000 - Nashville",
        "25.03.000 - Florida": "L:/Revit/2_PROJECTS/2025/25.03.000 - Florida",
        "25.04.000 - Knoxville": "L:/Revit/2_PROJECTS/2025/25.04.000 - Knoxville",
        "25.05.000 - Chattanooga": "L:/Revit/2_PROJECTS/2025/25.05.000 - Chattanooga",
        "25.06.000 - Sarasota": "L:/Revit/2_PROJECTS/2025/25.06.000 - Sarasota",
        "25.07.000 - Charlotte": "L:/Revit/2_PROJECTS/2025/25.07.000 - Charlotte",
        "25.08.000 - Raleigh": "L:/Revit/2_PROJECTS/2025/25.08.000 - Raleigh",
        "25.09.000 - Loudoun": "L:/Revit/2_PROJECTS/2025/25.09.000 - Loudoun"
    }

    # Seed set of already-existing project folders to avoid reprocessing at startup
    processed_folders = get_existing_folders(city_map)
    logger.info(f"Initialized with {len(processed_folders)} existing folders")

    # ---------------------------
    # Start Watchdog observers—one per existing city folder
    # ---------------------------
    observers = []
    handlers = []
    for folder_name, lucid_folder in city_map.items():
        egnyte_folder = f"Z:/Shared/Projects/2025/{folder_name}"
        if os.path.exists(egnyte_folder):
            # Each observer uses its own handler instance
            handler = CityFolderHandler(city_map)
            handlers.append(handler)

            observer = Observer()
            # Non-recursive: only watch the immediate city folder, not deep trees
            observer.schedule(handler, path=egnyte_folder, recursive=False)
            observer.start()

            observers.append(observer)
            logger.info(f"Monitoring started for: {egnyte_folder}")
        else:
            # If a city folder isn't present, we simply skip it
            logger.warning(f"The folder '{egnyte_folder}' does not exist and will not be monitored.")

    # ---------------------------
    # Start the poller in the background to catch missed events
    # ---------------------------
    if handlers:  # Only start if at least one monitored folder exists
        # Use the first handler (its processed_folders is independent of others)
        polling_thread = Thread(
            target=poll_folders,
            args=(city_map, handlers[0], processed_folders),
            daemon=True  # Daemon so it won’t block shutdown
        )
        polling_thread.start()
    else:
        logger.warning("No valid folders found to monitor. Polling thread will not start.")

    # ---------------------------
    # Keep the main thread alive; allow Ctrl+C to stop cleanly
    # ---------------------------
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # On Ctrl+C: stop observers first, then join to ensure clean shutdown
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()
        logger.info("Stopped all observers and exiting.")
