# Ethical-Endpoint-Activity-Monitor

## ⚠️ ETHICAL AND EDUCATIONAL USE ONLY ⚠️

<img width="995" height="833" alt="image" src="https://github.com/user-attachments/assets/415645a0-69eb-4fe6-b028-a6885b227b31" />


This project implements an advanced endpoint activity monitor in Python. It is designed **solely for educational purposes** to understand the mechanisms of endpoint security, forensic data collection, and threat analysis. It captures various user and system interactions, logging them in a structured, encrypted format.

**Intended Learning Outcomes:**

* **Endpoint Telemetry:** Understanding what data can be collected from an endpoint.
* **Data Integrity & Confidentiality:** Implementing encryption for sensitive collected data.
* **Structured Logging:** Using JSON for parseable and analyzable logs.
* **Event Correlation:** Laying the groundwork for correlating different types of activities (keyboard, mouse, window changes).
* **Defensive Security:** How malicious actors collect data, and consequently, how defenders can detect and prevent such unauthorized monitoring.
* **Forensic Readiness:** Creating a robust, auditable log of system activities for authorized investigations.

**⛔ DISCLAIMER:**
**Deploying or using this monitor without explicit, informed, and written consent from the owner of the system is illegal and unethical in most jurisdictions. The creator of this project is not responsible for any misuse, illegal activities, or damage caused by this software. This software is provided "as is," without warranty of any kind.**

---

## Features

* **GUI Application:** A user-friendly graphical interface to easily control monitoring and decrypt logs.
* **Keyboard Activity Monitoring:** Logs all keyboard inputs (characters and special keys).
* **Mouse Click Monitoring:** Records mouse clicks, including coordinates and button used.
* **Active Window Tracking:** Logs changes in the active application window title, providing crucial context.
* **Structured Logging (JSON Lines):** All events are logged as JSON objects, making them easy to parse and integrate with analytical tools.
* **Log File Encryption (AES-256 GCM):** All logged data is encrypted at rest using a randomly generated, local key, ensuring confidentiality.
* **Basic Log Rotation:** Logs are automatically rotated daily (configurable) to manage file size.
* **Configurable Settings:** Customize monitoring preferences, log directory, stop key, and encryption via `config.ini`.
* **Decryption Utility:** A built-in command-line option to decrypt the collected log files, complemented by the GUI's decryption feature.

## Getting Started

### Prerequisites

* Python 3.7+ installed on your system.
* `pip` (Python package installer).

### Installation

* **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Important: Permissions!

This tool captures system-level input. **It requires special permissions to function correctly.**

* **macOS:** You **MUST** grant "Accessibility" and "Input Monitoring" permissions to the Terminal application (or IDE like VS Code/PyCharm) from which you run the script, or directly to the Python executable itself, in `System Settings` > `Privacy & Security`.
* **Windows:** Run your terminal or IDE **as an Administrator**.

### Running the Monitor (via GUI - Recommended)

1.  **Ensure `config.ini` exists:**
    The script will automatically create a default `config.ini` if it's not found on the first run. Review and customize this file to your needs.
    * **`encryption_key.bin`:** An encryption key will be automatically generated and saved in this file if it doesn't exist. **Keep this file secure! It's needed for decryption.**

2.  **Execute the GUI script:**
    ```bash
    python gui_app.py
    ```
    The GUI window will appear, allowing you to "Start Monitor" and interact with other features.

3.  **Monitor Output (GUI):**
    The GUI will display recent activity for live feedback. Full, detailed logs are written to encrypted files in the `logs/` directory.

4.  **Stop the Monitor (GUI):**
    Press the configured `STOP_KEY` (default: `Esc`) at any time on your keyboard to gracefully stop the monitoring process. The GUI status will update accordingly.

### Viewing and Decrypting Logs

Collected logs are stored in the `logs/` directory (e.g., `logs/activity_YYYY-MM-DD.jsonl`). These files are encrypted.

#### Decryption via GUI (Recommended)

1.  In the `gui_app.py` window, navigate to the "Decrypt Logs" section.
2.  Use "Browse Log" to select the encrypted `activity_YYYY-MM-DD.jsonl` file.
3.  Use "Browse Key" to select your `encryption_key.bin` file.
4.  (Optional) Specify an output file name/path.
5.  Click "Decrypt Selected Log". A new file with the decrypted (plaintext) JSON data will be saved.

#### Decryption via Command Line

For command-line decryption, use the `monitor_core.py` script with the `--decrypt` flag:

```bash

python monitor_core.py --decrypt --log_file logs/activity_YYYY-MM-DD.jsonl --key_file encryption_key.bin --output_file decrypted_activity_YYYY-MM-DD.jsonl
