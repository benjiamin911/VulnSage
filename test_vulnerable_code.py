"""
测试文件：包含多种安全漏洞的示例代码
用于演示 VulnSage 的检测能力
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. SQL 注入漏洞
def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 危险：直接拼接 SQL 查询
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# 2. 命令注入漏洞
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # 危险：直接使用用户输入执行系统命令
    result = os.system(f"ping -c 4 {host}")
    return f"Ping result: {result}"

# 3. 代码注入漏洞
@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    # 危险：使用 eval 执行用户输入
    result = eval(expression)
    return f"Result: {result}"

# 4. XSS 漏洞
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 危险：直接在模板中渲染用户输入
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# 5. 路径遍历漏洞
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # 危险：未验证文件路径
    with open(f"/var/www/files/{filename}", 'r') as f:
        return f.read()

# 6. 不安全的反序列化
@app.route('/load_data')
def load_user_data():
    data = request.args.get('data')
    # 危险：反序列化不可信数据
    user_obj = pickle.loads(data.encode())
    return str(user_obj)

# 7. 硬编码密码
DATABASE_PASSWORD = "admin123"
API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

def connect_to_database():
    # 危险：硬编码凭证
    conn = sqlite3.connect(f"postgresql://admin:{DATABASE_PASSWORD}@localhost/mydb")
    return conn

# 8. 弱加密
def hash_password(password):
    # 危险：使用 MD5 进行密码哈希
    return hashlib.md5(password.encode()).hexdigest()

# 9. 不安全的随机数
import random
def generate_token():
    # 危险：使用不安全的随机数生成器
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

# 10. SSRF 漏洞
import requests
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # 危险：未验证的 URL 请求
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)  # 危险：在生产环境中启用 debug 模式 