import re
import json
import base64
from argparse import ArgumentParser
import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = "57A891D97E332A9D"
DEBUG = False
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "upgrade-insecure-requests": "1",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-language": "zh-CN,zh;q=0.9",
    "priority": "u=0, i"
}

def aes_decrypt(ciphertext_base64, key, iv):
    if DEBUG:
        print("Key:", key, "Iv:", iv, "Cipher_Text:", ciphertext_base64)

    # 将 Base64 编码的密文解码为字节串
    ciphertext = base64.b64decode(ciphertext_base64)
    
    # 创建 AES 解密器对象，使用 CBC 模式
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    
    # 进行解密操作
    decrypted_data = cipher.decrypt(ciphertext)
    
    # 去除填充
    plaintext = unpad(decrypted_data, AES.block_size)
    
    # 将解密后的字节串转换为字符串
    return plaintext.decode('utf-8')

def get_m3u8_url(url:str) -> str:
    response = requests.get(url, headers=headers)
    html_txt = response.text
    html = BeautifulSoup(html_txt, "html.parser")
    res = ""
    for script in html.find_all("script"):
        if "player_aaaa" in script.text:
            player_info = json.loads(script.text.split("player_aaaa=", 1)[1])
            url = player_info["url"]
            res = "https://danmu.yhdmjx.com/m3u8.php?url=" + url
    return res

def get_iv_url(url:str) -> str:
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "priority": "u=0, i",
        "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "iframe",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "sec-fetch-storage-access": "active",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    html = BeautifulSoup(response.text, "html.parser")
    res, enc_url = "", "" 
    for script in html.find_all("script"):
        if "bt_token" in script.text:
            res = script.text.split("=")[1].strip()[1:-2]
        elif "getVideoInfo" in script.text:
            enc_url = re.findall("getVideoInfo\(\"([^()]+)\"\)", script.text)[0]
    return res, enc_url

def download(url:str, save_pth:str):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept-Encoding": "identity;q=1, *;q=0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
        "sec-ch-ua-mobile": "?0",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Dest": "video",
        "Sec-Fetch-Storage-Access": "active",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Range": "bytes=0-"
    }
    response = requests.get(url, headers=headers)
    with open(save_pth, "wb") as f:
        f.write(response.content)

def main(url:str, save_path:str):
    key = KEY
    m3u8_url = get_m3u8_url(url)
    iv, enc_url = get_iv_url(m3u8_url)
    if iv:
        dec_url = aes_decrypt(enc_url, key, iv)
        download(dec_url, save_path)

# 示例使用
if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--url", type=str, required=True)
    parser.add_argument("--save_path", type=str, required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.url and args.save_path:
        DEBUG = args.debug
        main(args.url, args.save_path)
