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

class TokenGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT Token Generator")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # 設置主題風格
        style = ttk.Style()
        style.theme_use('clam')
        
        # 創建主框架
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 建立標題標籤
        title_label = ttk.Label(main_frame, text="JWT Token Generator", font=("Arial", 18, "bold"))
        title_label.grid(column=0, row=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # 創建輸入框架
        input_frame = ttk.LabelFrame(main_frame, text="Configuration Settings", padding="10")
        input_frame.grid(column=0, row=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 添加輸入欄位
        self.subject_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.storefront_code_var = tk.StringVar()
        self.name_var = tk.StringVar()
        self.private_key_var = tk.StringVar()
        self.iat_offset_var = tk.IntVar(value=0)
        
        # 標籤和輸入欄位的配置
        ttk.Label(input_frame, text="Subject:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, width=50, textvariable=self.subject_var).grid(column=1, row=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(input_frame, text="API Key:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, width=50, textvariable=self.api_key_var).grid(column=1, row=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(input_frame, text="Storefront Code:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, width=50, textvariable=self.storefront_code_var).grid(column=1, row=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(input_frame, text="Name:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, width=50, textvariable=self.name_var).grid(column=1, row=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(input_frame, text="IAT Offset (minutes):").grid(column=0, row=4, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(input_frame, from_=-60, to=60, textvariable=self.iat_offset_var, width=5).grid(column=1, row=4, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Private Key:").grid(column=0, row=5, sticky=tk.W, padx=5, pady=5)
        private_key_frame = ttk.Frame(input_frame)
        private_key_frame.grid(column=1, row=5, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.private_key_text = tk.Text(private_key_frame, width=50, height=8, wrap=tk.WORD)
        self.private_key_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(private_key_frame, orient="vertical", command=self.private_key_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.private_key_text['yscrollcommand'] = scrollbar.set
        
        # 按鈕框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(column=0, row=2, sticky=(tk.W, tk.E), padx=5, pady=10)
        
        # 添加按鈕
        ttk.Button(button_frame, text="Load Config", command=self.load_config).grid(column=0, row=0, padx=5)
        ttk.Button(button_frame, text="Save Config", command=self.save_config).grid(column=1, row=0, padx=5)
        ttk.Button(button_frame, text="Generate Token", command=self.generate_token).grid(column=2, row=0, padx=5)
        
        # 結果框架
        result_frame = ttk.LabelFrame(main_frame, text="Generated Token", padding="10")
        result_frame.grid(column=0, row=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 添加結果文本框
        self.result_text = tk.Text(result_frame, wrap=tk.WORD, width=80, height=10)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        result_scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text['yscrollcommand'] = result_scrollbar.set
        
        # 添加複製按鈕
        ttk.Button(main_frame, text="Copy Token", command=self.copy_token).grid(column=0, row=4, sticky=tk.E, padx=5, pady=5)
        
        # 狀態欄
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 嘗試載入默認配置
        try:
            self.load_default_config()
        except Exception as e:
            messagebox.showwarning("Warning", f"Could not load default config: {str(e)}")

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
        result = f"===== 生成的JWT Token =====\n{token}\n\n"
        result += f"===== Token詳細信息 =====\n"
        result += f"storefrontStoreCode: {config.get('storefrontStoreCode', '')}\n"
        result += f"IAT時間: {iat_time}\n\n"
        result += f"===== 使用說明 =====\n"
        result += "1. 請將此Token用於API請求的Authorization頭部或相應參數 x-auth-token: {token}\n"
        result += "2. Token僅在生成後30分鐘內有效\n"
        result += "3. Token的IAT時間偏移可通過設置IAT Offset參數調整\n"
        
        # 顯示IAT時間偏移信息
        if self.iat_offset_var.get() != 0:
            result += f"\n註：此Token的IAT（簽發時間）已偏移 {self.iat_offset_var.get()} 分鐘"
        
        self.result_text.insert(tk.END, result)
    
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
                if i > 0 and line.strip() and not line.startswith('====='):
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