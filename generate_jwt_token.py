#!/usr/bin/env python
import jwt
import json
import time
import argparse
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_config(config_path):
    """載入配置文件"""
    try:
        with open(config_path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"無法載入配置文件: {str(e)}")
        exit(1)

def generate_token(config, private_key, iat_offset_minutes=0):
    """生成JWT Token"""
    now = int(time.time())
    
    # 根據偏移量調整iat時間
    adjusted_iat = now + (iat_offset_minutes * 60)
    
    # 準備JWT Payload
    payload = {
        'sub': config.get('subject', 'shoalter'),
        'iat': adjusted_iat,
        'x-api-key': config.get('api_key')
    }
    
    # 可選：添加更多字段
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
        print(f"無法載入私鑰: {str(e)}")
        exit(1)
    
    # 生成JWT token
    try:
        token = jwt.encode(
            payload,
            private_key_obj,
            algorithm='RS256'
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token, adjusted_iat
    except Exception as e:
        print(f"生成Token失敗: {str(e)}")
        exit(1)

def format_iat_time(iat_timestamp):
    """將時間戳格式化為指定格式 (YYYYMMDD HH:MM:SS)"""
    dt = datetime.fromtimestamp(iat_timestamp)
    return dt.strftime("%Y%m%d %H:%M:%S")

def save_token_result(token, config, iat_timestamp, output_file="jwt_token_result.json"):
    """將token結果保存到JSON文件"""
    # 獲取當前時間作為生成時間
    generated_time = datetime.now().strftime("%Y%m%d %H:%M:%S")
    
    result = {
        "jwt_token": token,
        "storefrontStoreCode": config.get("storefrontStoreCode", ""),
        "iat_time": format_iat_time(iat_timestamp),
        "generated_time": generated_time
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nToken詳細信息已保存至: {output_file}")
    except Exception as e:
        print(f"保存Token詳細信息失敗: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='生成JWT Token')
    parser.add_argument('--config', default='config.json', help='配置文件路徑')
    parser.add_argument('--iat-offset', type=int, default=0, help='IAT時間偏移（分鐘）。正值表示未來時間，負值表示過去時間')
    parser.add_argument('--output', default='jwt_token_result.json', help='Token結果輸出文件路徑')
    args = parser.parse_args()
    
    # 載入配置
    config = load_config(args.config)
    
    # 生成或載入RSA密鑰
    private_key = config.get('private_key')
    
    # 生成Token
    token, iat_timestamp = generate_token(config, private_key, args.iat_offset)
    
    # 保存Token結果到JSON文件
    save_token_result(token, config, iat_timestamp, args.output)
    
    # 輸出結果
    print("\n===== 生成的JWT Token =====")
    print(token)
    print("\n===== Token詳細信息 =====")
    print(f"storefrontStoreCode: {config.get('storefrontStoreCode', '')}")
    print(f"IAT時間: {format_iat_time(iat_timestamp)}")
    print("\n===== 使用說明 =====")
    print("1. 請將此Token用於API請求的Authorization頭部或相應參數 x-auth-token: {token}")
    print("2. Token僅在生成後30分鐘內有效")
    print("3. Token的IAT時間偏移可通過 --iat-offset 參數設置")
    
    # 顯示IAT時間偏移信息
    if args.iat_offset != 0:
        print(f"\n註：此Token的IAT（簽發時間）已偏移 {args.iat_offset} 分鐘")

if __name__ == "__main__":
    main()