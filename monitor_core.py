import threading
import time
import os
import json
from datetime import datetime
from queue import Queue
import sys

# Try importing platform-specific modules for input monitoring
try:
    from pynput import keyboard, mouse
except ImportError:
    print("ERROR: pynput not installed. Please install it: pip install pynput")
    sys.exit(1)

# Try importing window management module
try:
    import pygetwindow as gw
except ImportError:
    print("ERROR: pygetwindow not installed. Please install it: pip install pygetwindow")
    sys.exit(1)

# Try importing psutil for process info
try:
    import psutil
except ImportError:
    print("ERROR: psutil not installed. Please install it: pip install psutil")
    sys.exit(1)

# Try importing encryption modules
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("ERROR: PyCryptodome not installed. Please install it: pip install pycryptodome")
    sys.exit(1)

# --- Configuration (loaded from config.ini) ---
import configparser

config = configparser.ConfigParser()
CONFIG_FILE = 'config.ini'

# Default configuration
DEFAULT_CONFIG = {
    'Logging': {
        'log_directory': 'logs',
        'log_file_name_prefix': 'activity',
        'log_rotation_interval_hours': '24'  # Rotate daily by default
    },
    'Encryption': {
        'enable_encryption': 'yes',
        'encryption_key_path': 'encryption_key.bin'
    },
    'Control': {
        'stop_key': 'esc'  # Default stop key
    },
    'Monitoring': {
        'monitor_keyboard': 'yes',
        'monitor_mouse_clicks': 'yes',
        'log_active_window_changes': 'yes'
    }
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] config.ini not found. Creating default configuration.")
        for section, options in DEFAULT_CONFIG.items():
            config[section] = options
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
    else:
        config.read(CONFIG_FILE)

    # Ensure all default sections/options exist after reading
    for section, options in DEFAULT_CONFIG.items():
        if section not in config:
            config[section] = {}
        for key, value in options.items():
            if key not in config[section]:
                config[section][key] = value

    # Save back if new defaults were added
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)


load_config()

# Global variables from config
LOG_DIRECTORY = config.get('Logging', 'log_directory')
LOG_FILE_PREFIX = config.get('Logging', 'log_file_name_prefix')
LOG_ROTATION_INTERVAL_HOURS = config.getint('Logging', 'log_rotation_interval_hours')
ENABLE_ENCRYPTION = config.getboolean('Encryption', 'enable_encryption')
LOG_ENCRYPTION_KEY_PATH = config.get('Encryption', 'encryption_key_path')
STOP_KEY = config.get('Control', 'stop_key').lower()
MONITOR_KEYBOARD = config.getboolean('Monitoring', 'monitor_keyboard')
MONITOR_MOUSE_CLICKS = config.getboolean('Monitoring', 'monitor_mouse_clicks')
LOG_ACTIVE_WINDOW_CHANGES = config.getboolean('Monitoring', 'log_active_window_changes')

# --- Encryption Setup ---
ENCRYPTION_KEY = None
SALT = b'spectre_eye_salt'  # A constant salt for PBKDF2


def derive_key(password: bytes, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive a consistent key from a password and salt."""
    return PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA512)


def generate_or_load_key():
    global ENCRYPTION_KEY
    if not os.path.exists(LOG_ENCRYPTION_KEY_PATH):
        try:
            # Generate a random password for the key derivation
            random_password = get_random_bytes(32)
            ENCRYPTION_KEY = derive_key(random_password, SALT)
            with open(LOG_ENCRYPTION_KEY_PATH, 'wb') as f:
                f.write(random_password)  # Save the password, not the derived key
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Encryption key generated and saved to {LOG_ENCRYPTION_KEY_PATH}")
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Failed to generate encryption key: {e}")
            global ENABLE_ENCRYPTION
            ENABLE_ENCRYPTION = False  # Disable encryption if key generation fails
    else:
        try:
            with open(LOG_ENCRYPTION_KEY_PATH, 'rb') as f:
                random_password = f.read()
            ENCRYPTION_KEY = derive_key(random_password, SALT)
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Encryption key loaded from {LOG_ENCRYPTION_KEY_PATH}")
        except Exception as e:
            print(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Failed to load encryption key: {e}. Disabling encryption.", )
            ENABLE_ENCRYPTION = False


def encrypt_data(data: str) -> bytes:
    if not ENABLE_ENCRYPTION or ENCRYPTION_KEY is None:
        return data.encode('utf-8')  # Return as bytes even if not encrypted

    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode('utf-8'), AES.block_size))
        return cipher.nonce + tag + ciphertext
    except Exception as e:
        print(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Encryption failed: {e}. Saving unencrypted data.")
        return data.encode('utf-8')


def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    try:
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_padded_data = cipher.decrypt_and_verify(ciphertext, tag)
        return unpad(decrypted_padded_data, AES.block_size).decode('utf-8')
    except (ValueError, KeyError, TypeError) as e:
        # print(f"Decryption error: {e}. Key or data may be corrupt/incorrect.")
        return f"DECRYPTION_ERROR: {e}"
    except Exception as e:
        # print(f"An unexpected error occurred during decryption: {e}")
        return f"DECRYPTION_ERROR: {e}"


# --- Global Monitor Control ---
monitor_running = False
event_queue = Queue()  # Queue for communication between monitor thread and GUI
monitor_thread = None  # <--- ADDED THIS LINE TO INITIALIZE

# --- Logging Setup ---
current_log_file = None
last_rotation_time = None
last_active_window = None


def get_log_file_path():
    timestamp = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIRECTORY, f"{LOG_FILE_PREFIX}_{timestamp}.jsonl")


def rotate_log_file():
    global current_log_file, last_rotation_time

    new_log_file_path = get_log_file_path()

    if current_log_file is None or \
            (datetime.now() - last_rotation_time).total_seconds() / 3600 >= LOG_ROTATION_INTERVAL_HOURS or \
            new_log_file_path != current_log_file.name:  # Check if date changed

        if current_log_file:
            current_log_file.close()
            event_queue.put(f"Log file rotated. Closed: {os.path.basename(current_log_file.name)}")

        os.makedirs(LOG_DIRECTORY, exist_ok=True)
        current_log_file = open(new_log_file_path, 'ab')  # 'ab' for append binary
        last_rotation_time = datetime.now()
        event_queue.put(f"Logging to: {os.path.basename(new_log_file_path)}")

    return current_log_file


def write_activity_event(event_type: str, data: dict, process_name: str = None, process_path: str = None,
                         pid: int = None):
    """
    Writes an activity event to the current log file.
    Includes process_name, process_path, and pid for window changes.
    """
    global current_log_file

    if not monitor_running:
        return

    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],  # Milliseconds
        "event_type": event_type,
        "data": data
    }

    # Add process info if available and relevant
    if process_name and process_path and pid is not None:
        log_entry["process_info"] = {
            "name": process_name,
            "path": process_path,
            "pid": pid
        }

    json_line = json.dumps(log_entry, ensure_ascii=False) + '\n'

    try:
        log_file = rotate_log_file()
        encrypted_line = encrypt_data(json_line)
        log_file.write(encrypted_line + b'\n')  # Add newline for each encrypted block
        log_file.flush()  # Ensure data is written to disk immediately
    except Exception as e:
        event_queue.put(f"ERROR: Failed to write to log file: {e}")


# --- Process Information Utility ---
def _get_process_info_from_pid(pid):
    """Helper to get process name and executable path from PID."""
    try:
        process = psutil.Process(pid)
        return process.name(), process.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A", "N/A"
    except Exception as e:
        event_queue.put(f"ERROR: Failed to get process info for PID {pid}: {e}")
        return "N/A", "N/A"


# --- Input Monitoring Callbacks ---
def on_press(key):
    try:
        char = key.char
    except AttributeError:
        char = str(key)  # Special keys (e.g., Key.space, Key.enter)

    if MONITOR_KEYBOARD:
        write_activity_event("keyboard_press", {"key": char})
        event_queue.put(f"[KEY] {char}")  # Send to GUI

    # Check for the stop key
    if STOP_KEY and char and char.lower() == STOP_KEY:
        event_queue.put(f"Stop key '{STOP_KEY}' pressed. Stopping monitor...")
        stop_monitor_gui_thread()  # Use the GUI-aware stop


def on_click(x, y, button, pressed):
    if MONITOR_MOUSE_CLICKS and pressed:  # Only log mouse down events
        write_activity_event("mouse_click", {"x": x, "y": y, "button": str(button)})
        event_queue.put(f"[CLICK] x:{x}, y:{y}, button:{str(button).replace('Button.', '')}")  # Send to GUI


def on_window_change(window):
    global last_active_window
    if LOG_ACTIVE_WINDOW_CHANGES and window and window.title != last_active_window:
        current_window_title = window.title

        process_name = "N/A"
        process_path = "N/A"
        pid = None

        # Try to get PID from pygetwindow object
        try:
            pid = window.pid
            if pid is not None:
                process_name, process_path = _get_process_info_from_pid(pid)
        except AttributeError:  # Some window objects might not have a .pid attribute
            pass  # PID will remain None, process info will be N/A
        except Exception as e:
            event_queue.put(f"ERROR: Failed to get PID from window object: {e}")

        write_activity_event("window_change",
                             {"title": current_window_title},
                             process_name=process_name,
                             process_path=process_path,
                             pid=pid)

        event_queue.put(f"[WINDOW] {current_window_title} (PID: {pid}, App: {process_name})")  # Send to GUI
        last_active_window = current_window_title


# --- Main Monitor Control ---
keyboard_listener = None
mouse_listener = None
window_listener_thread = None
stop_event = threading.Event()


def start_monitor():
    global keyboard_listener, mouse_listener, window_listener_thread, monitor_running, last_rotation_time, last_active_window, current_log_file, stop_event

    if monitor_running:
        event_queue.put("Monitor is already running.")
        return False

    # Initialize encryption key
    if ENABLE_ENCRYPTION:
        generate_or_load_key()
        if not ENABLE_ENCRYPTION:  # Check if it was disabled due to key error
            event_queue.put("Encryption disabled due to key error. Proceeding without encryption.")

    # Initialize log file
    try:
        os.makedirs(LOG_DIRECTORY, exist_ok=True)
        current_log_file = open(get_log_file_path(), 'ab')
        last_rotation_time = datetime.now()
        event_queue.put(f"Starting to log to: {os.path.basename(current_log_file.name)}")
    except Exception as e:
        event_queue.put(f"ERROR: Could not open log file: {e}. Monitor will not start.")
        return False

    monitor_running = True
    stop_event.clear()  # Clear the stop event for a fresh start

    # Start Keyboard Listener
    if MONITOR_KEYBOARD:
        keyboard_listener = keyboard.Listener(on_press=on_press)
        keyboard_listener.start()
        event_queue.put("Keyboard monitoring started.")

    # Start Mouse Listener
    if MONITOR_MOUSE_CLICKS:
        mouse_listener = mouse.Listener(on_click=on_click)
        mouse_listener.start()
        event_queue.put("Mouse monitoring started.")

    # Start Window Change Listener (in a separate thread for continuous polling)
    if LOG_ACTIVE_WINDOW_CHANGES:
        last_active_window = gw.getActiveWindowTitle()  # Set initial window title

        # Get initial process info for the active window
        initial_process_name = "N/A"
        initial_process_path = "N/A"
        initial_pid = None
        try:
            active_window_obj = gw.getActiveWindow()
            if active_window_obj and active_window_obj.pid is not None:
                initial_pid = active_window_obj.pid
                initial_process_name, initial_process_path = _get_process_info_from_pid(initial_pid)
        except Exception:
            pass  # Ignore errors if initial window/PID can't be fetched

        write_activity_event("window_change",
                             {"title": last_active_window},
                             process_name=initial_process_name,
                             process_path=initial_process_path,
                             pid=initial_pid)

        window_listener_thread = threading.Thread(target=_window_poller)
        window_listener_thread.daemon = True  # Allow main program to exit even if this thread is running
        window_listener_thread.start()
        event_queue.put("Active window monitoring started.")

    event_queue.put("MONITOR_STARTED")  # Signal to GUI
    return True


def _window_poller():
    """Polls for active window changes."""
    global last_active_window
    while not stop_event.is_set():
        try:
            current_active_window = gw.getActiveWindow()
            if current_active_window and current_active_window.title != last_active_window:
                on_window_change(current_active_window)
        except Exception as e:
            # Handle cases where window might be inaccessible briefly (e.g., system dialogs)
            # print(f"Window poller error: {e}") # Uncomment for debugging if needed
            pass
        time.sleep(0.5)  # Poll every 0.5 seconds


def stop_monitor():
    global keyboard_listener, mouse_listener, window_listener_thread, monitor_running, current_log_file, stop_event

    if not monitor_running:
        return

    event_queue.put("Stopping all listeners...")

    if keyboard_listener:
        keyboard_listener.stop()
        keyboard_listener.join(timeout=1)  # Give it a moment to stop
        keyboard_listener = None
        event_queue.put("Keyboard listener stopped.")

    if mouse_listener:
        mouse_listener.stop()
        mouse_listener.join(timeout=1)
        mouse_listener = None
        event_queue.put("Mouse listener stopped.")

    if window_listener_thread:
        stop_event.set()  # Signal the poller thread to stop
        window_listener_thread.join(timeout=1)
        window_listener_thread = None
        event_queue.put("Window listener stopped.")

    if current_log_file:
        current_log_file.close()
        current_log_file = None
        event_queue.put("Log file closed.")

    monitor_running = False
    event_queue.put("MONITOR_STOPPED")  # Signal to GUI


# --- Functions called by GUI ---
def start_monitor_gui_thread():
    """Starts the monitor in a separate thread so GUI remains responsive."""
    global monitor_thread  # This makes sure we refer to the global variable
    if monitor_thread and monitor_thread.is_alive():
        event_queue.put("Monitor thread already active.")
        return False

    monitor_thread = threading.Thread(target=start_monitor)
    monitor_thread.daemon = True  # Allows the main program (GUI) to exit even if this thread is running
    monitor_thread.start()
    return True


def stop_monitor_gui_thread():
    """Stops the monitor."""
    stop_monitor()


# --- Decryption Utility (for command line or GUI) ---
def decrypt_log_file_utility(encrypted_log_path, key_file_path, output_file_path):
    """Decrypts an encrypted log file using a given key."""
    if not os.path.exists(encrypted_log_path):
        print(f"Error: Encrypted log file not found at '{encrypted_log_path}'")
        return False
    if not os.path.exists(key_file_path):
        print(f"Error: Key file not found at '{key_file_path}'")
        return False

    try:
        with open(key_file_path, 'rb') as f:
            random_password = f.read()
        decryption_key = derive_key(random_password, SALT)
        print(f"Key loaded from '{key_file_path}' for decryption.")
    except Exception as e:
        print(f"Error loading decryption key from '{key_file_path}': {e}")
        return False

    try:
        with open(encrypted_log_path, 'rb') as infile, \
                open(output_file_path, 'w', encoding='utf-8') as outfile:

            for line_bytes in infile:
                # Remove trailing newline from encrypted block if present
                if line_bytes.endswith(b'\n'):
                    line_bytes = line_bytes[:-1]

                if not line_bytes:  # Skip empty lines
                    continue

                try:
                    decrypted_line = decrypt_data(line_bytes, decryption_key)
                    if decrypted_line.startswith("DECRYPTION_ERROR:"):
                        outfile.write(f"[[DECRYPTION FAILED]]: {line_bytes.hex()} - {decrypted_line}\n")
                    else:
                        outfile.write(decrypted_line + '\n')
                except Exception as e:
                    outfile.write(f"[[UNEXPECTED DECRYPTION ERROR]]: {line_bytes.hex()} - {e}\n")
        print(f"Log decrypted successfully to '{output_file_path}'")
        return True
    except Exception as e:
        print(f"Error during log decryption process: {e}")
        return False


# --- Command Line Interface for Decryption ---
if __name__ == "__main__":
    # Check for command line arguments for decryption
    if "--decrypt" in sys.argv:
        parser = configparser.ArgumentParser(description="Decrypt SpectreEye activity logs.")
        parser.add_argument("--decrypt", action="store_true", help="Initiate decryption mode.")
        parser.add_argument("--log_file", required=True, help="Path to the encrypted log file.")
        parser.add_argument("--key_file", required=True, help="Path to the encryption key file.")
        parser.add_argument("--output_file", required=True, help="Path for the decrypted output file.")

        args = parser.parse_args()

        print(f"Attempting to decrypt '{args.log_file}' using key '{args.key_file}' to '{args.output_file}'...")
        success = decrypt_log_file_utility(args.log_file, args.key_file, args.output_file)
        if success:
            print("Decryption finished.")
        else:
            print("Decryption failed.")
    else:
        # If run directly without --decrypt, it's typically for internal testing
        # The GUI now acts as the primary entry point for monitoring.
        print("This script is primarily designed to be run via gui_app.py for monitoring.")
        print("Use --decrypt flag for command-line decryption utility.")
        print(
            "Example: python monitor_core.py --decrypt --log_file logs/activity_YYYY-MM-DD.jsonl --key_file encryption_key.bin --output_file decrypted_output.jsonl")