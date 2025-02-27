#!/usr/bin/env python
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
import jwt
import time
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from PIL import Image, ImageTk
import io

class ModernUI:
    """Modern UI styling class"""
    # Modern color palette
    COLORS = {
        "primary": "#1976D2",  # Blue
        "primary_light": "#BBDEFB", 
        "primary_dark": "#0D47A1",
        "secondary": "#26C6DA",  # Cyan
        "secondary_light": "#B2EBF2",
        "accent": "#FF5722",  # Deep Orange
        "background": "#F5F5F5",  # Light grey
        "surface": "#FFFFFF",  # White
        "text_primary": "#212121",  # Dark grey
        "text_secondary": "#757575",  # Medium grey
        "divider": "#BDBDBD",  # Light grey
    }
    
    # Modern styles
    STYLES = {
        "font": ("Segoe UI", 10),
        "heading": ("Segoe UI", 18, "bold"),
        "subheading": ("Segoe UI", 14, "bold"),
        "button_padding": 10,
        "widget_radius": 4,
        "section_padding": 15
    }
    
    @classmethod
    def apply_styles(cls, root):
        style = ttk.Style()
        
        # Configure the base theme
        style.theme_use('clam')
        
        # Configure TFrame
        style.configure("TFrame", background=cls.COLORS["background"])
        style.configure("Card.TFrame", background=cls.COLORS["surface"], 
                        relief="flat", borderwidth=0)
        
        # Configure TLabelframe
        style.configure("TLabelframe", background=cls.COLORS["background"], 
                        foreground=cls.COLORS["text_primary"], 
                        font=cls.STYLES["subheading"])
        style.configure("TLabelframe.Label", 
                        font=cls.STYLES["subheading"],
                        background=cls.COLORS["background"], 
                        foreground=cls.COLORS["primary_dark"])
        
        # Configure TLabel
        style.configure("TLabel", background=cls.COLORS["background"], 
                        foreground=cls.COLORS["text_primary"], 
                        font=cls.STYLES["font"])
        style.configure("Title.TLabel", 
                        font=cls.STYLES["heading"],
                        foreground=cls.COLORS["primary_dark"], 
                        background=cls.COLORS["background"])
        
        # Configure TEntry
        style.configure("TEntry", 
                        fieldbackground=cls.COLORS["surface"], 
                        foreground=cls.COLORS["text_primary"],
                        bordercolor=cls.COLORS["primary_light"],
                        lightcolor=cls.COLORS["primary_light"],
                        darkcolor=cls.COLORS["primary_light"])
        style.map("TEntry", 
                  fieldbackground=[('focus', cls.COLORS["surface"])],
                  bordercolor=[('focus', cls.COLORS["primary"])])
        
        # Configure TButton
        style.configure("TButton", 
                        background=cls.COLORS["primary"],
                        foreground=cls.COLORS["surface"], 
                        font=cls.STYLES["font"],
                        borderwidth=0,
                        focuscolor=cls.COLORS["primary_dark"],
                        padding=cls.STYLES["button_padding"])
        style.map("TButton",
                  background=[('active', cls.COLORS["primary_dark"]), 
                             ('pressed', cls.COLORS["primary_dark"])],
                  relief=[('pressed', 'flat'), ('!pressed', 'flat')])
                  
        # Accent button
        style.configure("Accent.TButton", 
                        background=cls.COLORS["accent"],
                        foreground=cls.COLORS["surface"])
        style.map("Accent.TButton",
                  background=[('active', "#E64A19"), 
                             ('pressed', "#BF360C")])
                             
        # Secondary button
        style.configure("Secondary.TButton", 
                        background=cls.COLORS["secondary"],
                        foreground=cls.COLORS["surface"])
        style.map("Secondary.TButton",
                  background=[('active', "#00ACC1"), 
                             ('pressed', "#00838F")])
        
        # Configure TSpinbox
        style.configure("TSpinbox", 
                        background=cls.COLORS["surface"],
                        fieldbackground=cls.COLORS["surface"], 
                        foreground=cls.COLORS["text_primary"],
                        arrowcolor=cls.COLORS["primary"])
                        
        # Configure Horizontal TSeparator
        style.configure("TSeparator", 
                        background=cls.COLORS["divider"])
        
        # Set global background                
        root.configure(background=cls.COLORS["background"])

class TokenGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT Token Generator")
        
        # Increase initial window size for better visibility
        self.root.geometry("1000x750")
        self.root.minsize(1000, 750)
        self.root.resizable(True, True)
        
        # Center the window on screen
        self.center_window(1000, 750)
        
        # Apply modern styling
        ModernUI.apply_styles(root)
        
        # Create a main container frame with padding
        container = ttk.Frame(root, style="TFrame", padding="20")
        container.pack(fill=tk.BOTH, expand=True)
        
        # Create a header section
        header_frame = ttk.Frame(container, style="TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Application title 
        title_label = ttk.Label(header_frame, text="JWT Token Generator", style="Title.TLabel")
        title_label.pack(side=tk.LEFT, padx=5)
        
        # Create a horizontal separator below header
        separator = ttk.Separator(container, orient='horizontal')
        separator.pack(fill=tk.X, pady=(0, 20))
        
        # Main content area - using grid layout for better control
        content_frame = ttk.Frame(container, style="TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure column weights to ensure proper sizing
        content_frame.columnconfigure(0, weight=1)   # Left column
        content_frame.columnconfigure(1, weight=1)   # Right column
        content_frame.rowconfigure(0, weight=1)      # Both columns expand vertically
        
        # Left column for configuration (using grid now)
        left_column = ttk.Frame(content_frame, style="TFrame", padding=(0, 0, 10, 0))
        left_column.grid(row=0, column=0, sticky="nsew")
        
        # Right column for results (using grid now)
        right_column = ttk.Frame(content_frame, style="TFrame", padding=(10, 0, 0, 0))
        right_column.grid(row=0, column=1, sticky="nsew")
        
        # Make sure both columns expand
        left_column.columnconfigure(0, weight=1)
        right_column.columnconfigure(0, weight=1)
        left_column.rowconfigure(0, weight=1)
        right_column.rowconfigure(0, weight=1)
        
        # Create configuration section in the left column
        config_frame = ttk.LabelFrame(left_column, text="Configuration Settings", padding=ModernUI.STYLES["section_padding"])
        config_frame.grid(row=0, column=0, sticky="nsew")
        
        # Variables for input fields
        self.subject_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.storefront_code_var = tk.StringVar()
        self.name_var = tk.StringVar()
        self.private_key_var = tk.StringVar()
        self.iat_offset_var = tk.IntVar(value=0)
        
        # Create grid for form fields
        form_frame = ttk.Frame(config_frame, style="TFrame")
        form_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        form_frame.columnconfigure(1, weight=1)
        
        # Input fields
        row = 0
        for label_text, var in [
            ("Subject:", self.subject_var),
            ("API Key:", self.api_key_var),
            ("Storefront Code:", self.storefront_code_var),
            ("Name:", self.name_var)
        ]:
            ttk.Label(form_frame, text=label_text).grid(
                column=0, row=row, sticky=tk.W, padx=(0, 10), pady=10)
            ttk.Entry(form_frame, textvariable=var).grid(
                column=1, row=row, sticky=(tk.W, tk.E), pady=10)
            row += 1

        # IAT Offset with spinbox
        ttk.Label(form_frame, text="IAT Offset (minutes):").grid(
            column=0, row=row, sticky=tk.W, padx=(0, 10), pady=10)
        ttk.Spinbox(form_frame, from_=-60, to=60, textvariable=self.iat_offset_var, width=10).grid(
            column=1, row=row, sticky=tk.W, pady=10)
        row += 1
        
        # Private Key text area
        ttk.Label(form_frame, text="Private Key:").grid(
            column=0, row=row, sticky=tk.NW, padx=(0, 10), pady=10)
        
        private_key_frame = ttk.Frame(form_frame, style="TFrame")
        private_key_frame.grid(column=1, row=row, sticky=(tk.W, tk.E), pady=10)
        private_key_frame.columnconfigure(0, weight=1)
        
        self.private_key_text = tk.Text(
            private_key_frame, 
            height=8, 
            wrap=tk.WORD, 
            bg=ModernUI.COLORS["surface"],
            fg=ModernUI.COLORS["text_primary"],
            relief="flat",
            font=ModernUI.STYLES["font"],
            padx=8,
            pady=8,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=ModernUI.COLORS["primary_light"],
            highlightcolor=ModernUI.COLORS["primary"]
        )
        self.private_key_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(private_key_frame, orient="vertical", command=self.private_key_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.private_key_text['yscrollcommand'] = scrollbar.set
        
        # Configuration action buttons
        button_frame = ttk.Frame(left_column, style="TFrame")
        button_frame.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        
        ttk.Button(button_frame, text="Load Config", style="Secondary.TButton", command=self.load_config).pack(
            side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save Config", style="Secondary.TButton", command=self.save_config).pack(
            side=tk.LEFT, padx=(0, 10))
        
        # Result section in the right column
        result_frame = ttk.LabelFrame(right_column, text="Generated Token", padding=ModernUI.STYLES["section_padding"])
        result_frame.grid(row=0, column=0, sticky="nsew")
        
        # Make sure result frame expands properly
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        # Result text area with modern styling
        result_container = ttk.Frame(result_frame, style="TFrame")
        result_container.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        
        self.result_text = tk.Text(
            result_container, 
            wrap=tk.WORD, 
            height=15,
            bg=ModernUI.COLORS["surface"],
            fg=ModernUI.COLORS["text_primary"],
            relief="flat",
            font=ModernUI.STYLES["font"],
            padx=10,
            pady=10,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=ModernUI.COLORS["primary_light"],
            highlightcolor=ModernUI.COLORS["primary"]
        )
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        result_scrollbar = ttk.Scrollbar(result_container, orient="vertical", command=self.result_text.yview)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text['yscrollcommand'] = result_scrollbar.set
        
        # Action buttons for the results area
        action_frame = ttk.Frame(right_column, style="TFrame")
        action_frame.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        
        # Generate token button with larger size (accent color)
        generate_btn = ttk.Button(
            action_frame, 
            text="Generate Token", 
            style="Accent.TButton", 
            command=self.generate_token
        )
        generate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Copy token button
        copy_btn = ttk.Button(
            action_frame, 
            text="Copy Token", 
            command=self.copy_token
        )
        copy_btn.pack(side=tk.LEFT)
        
        # Status bar at the bottom of the main window
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            root, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            background=ModernUI.COLORS["primary_light"],
            foreground=ModernUI.COLORS["primary_dark"],
            padding=(10, 5)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Try to load default configuration
        try:
            self.load_default_config()
        except Exception as e:
            messagebox.showwarning("Warning", f"Could not load default config: {str(e)}")
            
        # Force update to ensure everything is laid out correctly
        self.root.update_idletasks()
    
    def center_window(self, width, height):
        """Center the window on the screen"""
        # Get screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Calculate position coordinates
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        # Set the window position
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def load_default_config(self):
        """嘗試載入默認配置文件"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as file:
                    config = json.load(file)
                    self.update_fields_from_config(config)
                    self.status_var.set("Default configuration loaded")
            except Exception as e:
                self.status_var.set(f"Error loading default configuration: {str(e)}")
    
    def update_fields_from_config(self, config):
        """從配置字典更新UI字段"""
        self.subject_var.set(config.get("subject", ""))
        self.api_key_var.set(config.get("api_key", ""))
        self.storefront_code_var.set(config.get("storefrontStoreCode", ""))
        
        # 處理額外的claims
        if "additional_claims" in config and "name" in config["additional_claims"]:
            self.name_var.set(config["additional_claims"]["name"])
        
        # 處理私鑰
        if "private_key" in config:
            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, config["private_key"])

    def get_config_from_fields(self):
        """從UI字段獲取配置字典"""
        config = {
            "subject": self.subject_var.get(),
            "api_key": self.api_key_var.get(),
            "storefrontStoreCode": self.storefront_code_var.get(),
            "additional_claims": {
                "name": self.name_var.get()
            },
            "private_key": self.private_key_text.get(1.0, tk.END).strip()
        }
        return config
    
    def load_config(self):
        """從文件載入配置"""
        file_path = filedialog.askopenfilename(
            title="選擇配置文件",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as file:
                config = json.load(file)
                self.update_fields_from_config(config)
                self.status_var.set(f"Configuration loaded from {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load configuration: {str(e)}")
    
    def save_config(self):
        """保存配置到文件"""
        config = self.get_config_from_fields()
        
        file_path = filedialog.asksaveasfilename(
            title="保存配置文件",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as file:
                json.dump(config, file, indent=4)
                self.status_var.set(f"Configuration saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save configuration: {str(e)}")
    
    def generate_token(self):
        """生成JWT令牌"""
        try:
            # 從UI獲取配置
            config = self.get_config_from_fields()
            private_key = config.get('private_key')
            iat_offset_minutes = self.iat_offset_var.get()
            
            # 生成時間戳
            now = int(time.time())
            adjusted_iat = now + (iat_offset_minutes * 60)
            
            # 準備JWT Payload
            payload = {
                'sub': config.get('subject', ''),
                'iat': adjusted_iat,
                'x-api-key': config.get('api_key', '')
            }
            
            # 添加額外字段
            if 'additional_claims' in config:
                payload.update(config['additional_claims'])
            
            # 載入私鑰
            try:
                private_key_obj = serialization.load_pem_private_key(
                    private_key.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            except Exception as e:
                raise Exception(f"Error loading private key: {str(e)}")
            
            # 生成JWT token
            token = jwt.encode(
                payload,
                private_key_obj,
                algorithm='RS256'
            )
            
            if isinstance(token, bytes):
                token = token.decode('utf-8')
            
            # 格式化IAT時間
            iat_time = self.format_iat_time(adjusted_iat)
            
            # 顯示結果
            self.display_result(token, config, iat_time)
            
            # 保存結果到文件
            self.save_token_result(token, config, adjusted_iat)
            
            self.status_var.set("Token generated successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate token: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")
    
    def format_iat_time(self, iat_timestamp):
        """將時間戳格式化為指定格式 (YYYYMMDD HH:MM:SS)"""
        dt = datetime.fromtimestamp(iat_timestamp)
        return dt.strftime("%Y%m%d %H:%M:%S")
    
    def display_result(self, token, config, iat_time):
        """在結果文本框中顯示令牌信息"""
        self.result_text.delete(1.0, tk.END)
        
        # Display token with styling
        self.result_text.tag_configure("header", font=("Segoe UI", 12, "bold"), foreground=ModernUI.COLORS["primary_dark"])
        self.result_text.tag_configure("token", font=("Consolas", 10), background="#F0F8FF", foreground="#0D47A1")
        self.result_text.tag_configure("subheader", font=("Segoe UI", 11, "bold"), foreground=ModernUI.COLORS["secondary"])
        self.result_text.tag_configure("info", foreground=ModernUI.COLORS["text_primary"])
        self.result_text.tag_configure("important", foreground=ModernUI.COLORS["accent"], font=("Segoe UI", 10, "bold"))
        
        self.result_text.insert(tk.END, "生成的JWT Token\n", "header")
        self.result_text.insert(tk.END, token + "\n\n", "token")
        
        self.result_text.insert(tk.END, "Token詳細信息\n", "subheader")
        self.result_text.insert(tk.END, f"storefrontStoreCode: {config.get('storefrontStoreCode', '')}\n", "info")
        self.result_text.insert(tk.END, f"IAT時間: {iat_time}\n\n", "info")
        
        self.result_text.insert(tk.END, "使用說明\n", "subheader")
        self.result_text.insert(tk.END, "1. 請將此Token用於API請求的Authorization頭部或相應參數\n", "info")
        self.result_text.insert(tk.END, "   x-auth-token: " + token[:20] + "...\n", "info")
        self.result_text.insert(tk.END, "2. Token僅在生成後30分鐘內有效\n", "info")
        self.result_text.insert(tk.END, "3. Token的IAT時間偏移可通過設置IAT Offset參數調整\n", "info")
        
        # 顯示IAT時間偏移信息
        if self.iat_offset_var.get() != 0:
            self.result_text.insert(tk.END, f"\n註：此Token的IAT（簽發時間）已偏移 {self.iat_offset_var.get()} 分鐘", "important")
    
    def save_token_result(self, token, config, iat_timestamp, output_file="jwt_token_result.json"):
        """將token結果保存到JSON文件"""
        # 獲取當前時間作為生成時間
        generated_time = datetime.now().strftime("%Y%m%d %H:%M:%S")
        
        result = {
            "jwt_token": token,
            "storefrontStoreCode": config.get("storefrontStoreCode", ""),
            "iat_time": self.format_iat_time(iat_timestamp),
            "generated_time": generated_time
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            messagebox.showwarning("Warning", f"Could not save token details: {str(e)}")
    
    def copy_token(self):
        """複製令牌到剪貼板"""
        try:
            # 獲取結果文本的第一個部分（僅令牌）
            text_content = self.result_text.get(1.0, tk.END)
            token_lines = text_content.split('\n')
            for i, line in enumerate(token_lines):
                if i > 0 and line.strip() and not line.startswith('生成的') and not line.startswith('Token') and not line.startswith('使用'):
                    token = line.strip()
                    self.root.clipboard_clear()
                    self.root.clipboard_append(token)
                    self.status_var.set("Token copied to clipboard")
                    return
            
            messagebox.showinfo("Info", "No token found to copy")
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy token: {str(e)}")

def main():
    root = tk.Tk()
    app = TokenGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()