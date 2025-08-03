import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import monitor_core as mc  # Import our core logic
import threading
import queue
import os
from PIL import Image, ImageTk  # Import Pillow for image handling


class MonitorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Ethical Endpoint Activity Monitor")
        master.geometry("800x650")
        master.configure(bg="black")

        self.monitor_running = False
        self.monitor_thread = None
        self.event_queue = mc.event_queue

        # --- Styles & Colors ---
        self.bg_color = "black"
        self.fg_color = "white"
        self.accent_color = "#00FF00"  # Neon Green for a 'cyber' feel
        self.entry_bg = "#333333"
        self.entry_fg = "#00FF00"
        self.button_bg = "#2c2c2c"
        self.button_fg = "white"
        self.button_active_bg = "#005500"
        self.button_active_fg = "white"
        self.border_color = "#00FF00"

        # --- Fonts ---
        self.label_font = ("Consolas", 10)
        self.button_font = ("Consolas", 10, "bold")
        self.status_font = ("Consolas", 11, "bold")
        self.log_font = ("Consolas", 9)
        self.heading_font = ("Consolas", 12, "bold")
        self.title_font = ("Consolas", 18, "bold")  # Larger font for main title

        # --- Header Frame (for Logo and Title) ---
        self.header_frame = tk.Frame(master, bg=self.bg_color, padx=15, pady=10)
        self.header_frame.pack(side=tk.TOP, fill=tk.X)

        # Load and display Logo
        self.logo_path = "spectre_eye_logo.jpg"  # <--- MAKE SURE THIS PATH IS CORRECT
        self.logo_image = None
        try:
            # Open image using Pillow
            img = Image.open(self.logo_path)
            # Resize if necessary (optional, adjust as needed)
            img = img.resize((48, 48), Image.LANCZOS)  # Resizing for a consistent look
            self.logo_image = ImageTk.PhotoImage(img)

            self.logo_label = tk.Label(self.header_frame, image=self.logo_image, bg=self.bg_color)
            self.logo_label.pack(side=tk.LEFT, padx=(0, 10))  # Pad to the right of logo
        except FileNotFoundError:
            print(f"WARNING: Logo file not found at {self.logo_path}. Skipping logo display.")
        except Exception as e:
            print(f"WARNING: Could not load logo image: {e}. Skipping logo display.")

        # Main Title Label
        self.title_label = tk.Label(self.header_frame, text="SpectreEye Monitor", fg=self.accent_color,
                                    bg=self.bg_color, font=self.title_font)
        self.title_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- Control Buttons Frame ---
        self.control_frame = tk.Frame(master, bg=self.bg_color, padx=15, pady=5)
        self.control_frame.pack(side=tk.TOP, fill=tk.X)

        self.status_frame = tk.Frame(master, bg=self.bg_color, padx=15, pady=5)
        self.status_frame.pack(side=tk.TOP, fill=tk.X)

        self.log_frame = tk.Frame(master, bg=self.bg_color, padx=15, pady=10)
        self.log_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.decrypt_frame = tk.Frame(master, bg=self.bg_color, padx=15, pady=10, relief=tk.GROOVE, bd=2,
                                      highlightbackground=self.border_color)
        self.decrypt_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=10)

        # --- Control Buttons ---
        self.start_button = tk.Button(self.control_frame, text="Start Monitor", command=self.start_monitor,
                                      bg=self.button_bg, fg=self.button_fg, font=self.button_font,
                                      activebackground=self.button_active_bg, activeforeground=self.button_active_fg,
                                      relief=tk.FLAT, bd=2, highlightbackground=self.border_color)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.control_frame, text="Stop Monitor (Press Esc)", command=self.stop_monitor,
                                     bg=self.button_bg, fg=self.button_fg, font=self.button_font,
                                     activebackground=self.button_active_bg, activeforeground=self.button_active_fg,
                                     relief=tk.FLAT, bd=2, highlightbackground=self.border_color, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # --- Status Display ---
        self.status_label = tk.Label(self.status_frame, text="Status: Idle", fg="cyan", bg=self.bg_color,
                                     font=self.status_font)
        self.status_label.pack(side=tk.LEFT, padx=5)

        # --- Real-time Log Display ---
        tk.Label(self.log_frame, text="Recent Activity (Live Feed):", fg=self.accent_color, bg=self.bg_color,
                 font=self.heading_font).pack(side=tk.TOP, anchor=tk.W, pady=(0, 5))
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, state=tk.DISABLED, height=15,
                                                  bg="black", fg=self.accent_color, font=self.log_font,
                                                  insertbackground=self.accent_color,
                                                  selectbackground="#003300", selectforeground="white",
                                                  relief=tk.FLAT, bd=2, highlightbackground=self.border_color,
                                                  highlightcolor=self.border_color)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # --- Decryption Section ---
        tk.Label(self.decrypt_frame, text="Decrypt Log Files:", fg=self.accent_color, bg=self.bg_color,
                 font=self.heading_font).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.log_file_path_label = tk.Label(self.decrypt_frame, text="Encrypted Log File:", fg=self.fg_color,
                                            bg=self.bg_color, font=self.label_font)
        self.log_file_path_label.grid(row=1, column=0, sticky="w", pady=2)
        self.log_file_path_entry = tk.Entry(self.decrypt_frame, width=50, bg=self.entry_bg, fg=self.entry_fg,
                                            insertbackground=self.accent_color, font=self.label_font)
        self.log_file_path_entry.grid(row=1, column=1, padx=5, sticky="ew", pady=2)
        self.browse_log_button = tk.Button(self.decrypt_frame, text="Browse Log", command=self.browse_log_file,
                                           bg=self.button_bg, fg=self.button_fg, font=self.label_font,
                                           activebackground=self.button_active_bg,
                                           activeforeground=self.button_active_fg, relief=tk.FLAT,
                                           highlightbackground=self.border_color)
        self.browse_log_button.grid(row=1, column=2, padx=5, pady=2)

        self.key_file_path_label = tk.Label(self.decrypt_frame, text="Encryption Key File:", fg=self.fg_color,
                                            bg=self.bg_color, font=self.label_font)
        self.key_file_path_label.grid(row=2, column=0, sticky="w", pady=2)
        self.key_file_path_entry = tk.Entry(self.decrypt_frame, width=50, bg=self.entry_bg, fg=self.entry_fg,
                                            insertbackground=self.accent_color, font=self.label_font)
        self.key_file_path_entry.grid(row=2, column=1, padx=5, sticky="ew", pady=2)
        self.browse_key_button = tk.Button(self.decrypt_frame, text="Browse Key", command=self.browse_key_file,
                                           bg=self.button_bg, fg=self.button_fg, font=self.label_font,
                                           activebackground=self.button_active_bg,
                                           activeforeground=self.button_active_fg, relief=tk.FLAT,
                                           highlightbackground=self.border_color)
        self.browse_key_button.grid(row=2, column=2, padx=5, pady=2)

        self.decrypt_output_path_label = tk.Label(self.decrypt_frame, text="Save Decrypted As:", fg=self.fg_color,
                                                  bg=self.bg_color, font=self.label_font)
        self.decrypt_output_path_label.grid(row=3, column=0, sticky="w", pady=2)
        self.decrypt_output_path_entry = tk.Entry(self.decrypt_frame, width=50, bg=self.entry_bg, fg=self.entry_fg,
                                                  insertbackground=self.accent_color, font=self.label_font)
        self.decrypt_output_path_entry.insert(0, "decrypted_output.jsonl")
        self.decrypt_output_path_entry.grid(row=3, column=1, padx=5, sticky="ew", pady=2)
        self.browse_output_button = tk.Button(self.decrypt_frame, text="Browse Output", command=self.browse_output_file,
                                              bg=self.button_bg, fg=self.button_fg, font=self.label_font,
                                              activebackground=self.button_active_bg,
                                              activeforeground=self.button_active_fg, relief=tk.FLAT,
                                              highlightbackground=self.border_color)
        self.browse_output_button.grid(row=3, column=2, padx=5, pady=2)

        self.decrypt_button = tk.Button(self.decrypt_frame, text="Decrypt Selected Log", command=self.decrypt_log,
                                        bg=self.accent_color, fg="black", font=self.button_font,
                                        activebackground="#00AA00", activeforeground="white", relief=tk.FLAT,
                                        highlightbackground=self.border_color)
        self.decrypt_button.grid(row=4, column=1, pady=15)

        self.decrypt_frame.grid_columnconfigure(1, weight=1)

        # Set default key file path if it exists
        if os.path.exists(mc.LOG_ENCRYPTION_KEY_PATH):
            self.key_file_path_entry.insert(0, mc.LOG_ENCRYPTION_KEY_PATH)

        # Start checking the queue for updates
        self.master.after(100, self.process_queue)

    def update_status(self, message, color="white"):
        self.status_label.config(text=f"Status: {message}", fg=color)

    def append_to_log_display(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def process_queue(self):
        """Periodically checks the queue for events from the monitor thread."""
        try:
            while True:
                message = self.event_queue.get_nowait()
                if message == "MONITOR_STARTED":
                    self.update_status("Monitoring Active", "lightgreen")
                    self.start_button.config(state=tk.DISABLED, bg=self.button_bg, fg="gray")
                    self.stop_button.config(state=tk.NORMAL, bg=self.button_bg, fg=self.button_fg)
                    self.append_to_log_display("--- Monitor Started ---")
                elif message == "MONITOR_STOPPED":
                    self.update_status("Monitoring Stopped", "cyan")
                    self.start_button.config(state=tk.NORMAL, bg=self.button_bg, fg=self.button_fg)
                    self.stop_button.config(state=tk.DISABLED, bg=self.button_bg, fg="gray")
                    self.append_to_log_display("--- Monitor Stopped ---")
                elif message.startswith("ERROR:"):
                    self.update_status(message, "red")
                    self.append_to_log_display(message)
                    self.start_button.config(state=tk.NORMAL, bg=self.button_bg, fg=self.button_fg)
                    self.stop_button.config(state=tk.DISABLED, bg=self.button_bg, fg="gray")
                else:
                    self.append_to_log_display(message)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def start_monitor(self):
        if not self.monitor_running:
            self.update_status("Starting Monitor...", "orange")
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.config(state=tk.DISABLED)

            if mc.start_monitor_gui_thread():
                self.monitor_running = True
            else:
                self.update_status("Failed to start monitor", "red")

    def stop_monitor(self):
        if self.monitor_running:
            self.update_status("Stopping Monitor...", "orange")
            mc.stop_monitor_gui_thread()
            self.monitor_running = False

    def browse_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Encrypted Log File",
            filetypes=(("JSONL Encrypted Files", "*.jsonl"), ("All files", "*.*")),
            initialdir=os.path.join(os.getcwd(), mc.LOG_DIRECTORY) if mc.LOG_DIRECTORY and os.path.exists(
                os.path.join(os.getcwd(), mc.LOG_DIRECTORY)) else os.getcwd()
        )
        if file_path:
            self.log_file_path_entry.delete(0, tk.END)
            self.log_file_path_entry.insert(0, file_path)

    def browse_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Encryption Key File",
            filetypes=(("Binary Files", "*.bin"), ("All files", "*.*")),
            initialdir=os.getcwd()
        )
        if file_path:
            self.key_file_path_entry.delete(0, tk.END)
            self.key_file_path_entry.insert(0, file_path)

    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Decrypted Log As",
            defaultextension=".jsonl",
            filetypes=(("JSONL Files", "*.jsonl"), ("Text Files", "*.txt"), ("All files", "*.*")),
            initialdir=os.getcwd()
        )
        if file_path:
            self.decrypt_output_path_entry.delete(0, tk.END)
            self.decrypt_output_path_entry.insert(0, file_path)

    def decrypt_log(self):
        encrypted_log_path = self.log_file_path_entry.get()
        key_file_path = self.key_file_path_entry.get()
        output_file_path = self.decrypt_output_path_entry.get()

        if not encrypted_log_path or not key_file_path or not output_file_path:
            messagebox.showerror("Decryption Error", "Please select all required files (Log, Key, Output).",
                                 parent=self.master)
            return

        self.update_status("Decrypting...", "orange")

        def decrypt_thread_target():
            success = mc.decrypt_log_file_utility(encrypted_log_path, key_file_path, output_file_path)
            if success:
                messagebox.showinfo("Decryption Complete", f"Log successfully decrypted to:\n{output_file_path}",
                                    parent=self.master)
                self.update_status("Decryption Complete", "lightgreen")
            else:
                messagebox.showerror("Decryption Failed",
                                     "Failed to decrypt log. Check key, log file, and console for errors.",
                                     parent=self.master)
                self.update_status("Decryption Failed", "red")

        decrypt_worker_thread = threading.Thread(target=decrypt_thread_target)
        decrypt_worker_thread.daemon = True
        decrypt_worker_thread.start()


if __name__ == "__main__":
    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()