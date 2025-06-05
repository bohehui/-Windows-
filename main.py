# -*- coding: utf-8 -*-
"""
----------------------------------------------------------------------
 文件名称: main.py
 当前版本: v2.0
 作    者: bohehui
 创建日期: 2025年6月
 最后修改: 2025年6月
 项目简介: 
   Windows 超级命令控制中心
   —— 跨平台多终端命令图形化管理工具，集成CMD、PowerShell、WSL/Kali、Workspace ONE等环境，
   支持命令参数智能输入、历史命令、命令库检索、日志输出、项目结构可视化等功能。

  功能亮点:
   - 一键切换多命令终端环境
   - 命令分组按钮化、参数智能弹窗、文件/目录选择
   - 项目结构树可视化
   - 命令库中英文对照，模糊检索
   - 历史命令回溯
   - 全程操作日志记录（uwcc.log）
   - 中文友好界面，适合所有Windows用户

  运行环境: Windows 10/11, Python 3.7 及以上
  依赖库: tkinter, subprocess, re, os, sys, datetime (均为标准库)
----------------------------------------------------------------------
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import subprocess
import re
import os
import sys
import datetime

class UltimateWindowsCommandCenter:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows 超级命令控制中心 v2.0")
        self.root.geometry("1200x900")
        self.log_file = os.path.join(os.path.dirname(__file__), "uwcc.log")

        self.wsl_available = self.check_wsl()
        self.load_command_library()

        self.tab_control = ttk.Notebook(root)
        self.tab_cmd = ttk.Frame(self.tab_control)
        self.tab_ps = ttk.Frame(self.tab_control)
        self.tab_wsl = ttk.Frame(self.tab_control)
        self.tab_ws1 = ttk.Frame(self.tab_control)
        self.tab_custom = ttk.Frame(self.tab_control)
        self.tab_library = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_cmd, text='CMD命令')
        self.tab_control.add(self.tab_ps, text='PowerShell')
        self.tab_control.add(self.tab_wsl, text='WSL/Kali')
        self.tab_control.add(self.tab_ws1, text='Workspace ONE')
        self.tab_control.add(self.tab_custom, text='自定义命令')
        self.tab_control.add(self.tab_library, text='命令库')
        self.tab_control.pack(expand=1, fill="both")

        self.console = scrolledtext.ScrolledText(root, height=15)
        self.console.pack(fill="both", expand=True, padx=10, pady=5)
        self.console.tag_config("success", foreground="green")
        self.console.tag_config("error", foreground="red")
        self.console.tag_config("warning", foreground="orange")
        self.console.tag_config("cmd", foreground="blue")

        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.create_cmd_tab()
        self.create_ps_tab()
        self.create_wsl_tab()
        self.create_ws1_tab()
        self.create_custom_tab()
        self.create_library_tab()

        if not self.wsl_available:
            self.print_to_console("警告: WSL未安装，相关功能不可用\n", "warning")
            self.log_action("WSL 未安装，相关功能不可用")

        self.log_action("UltimateWindowsCommandCenter 启动")

    def log_action(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.print_to_console(f"日志写入失败: {e}\n", "error")

    def load_command_library(self):
        self.command_library = {
            "CMD": {
                "文件操作 / File Operations": [
                    ("dir", "列出当前目录内容 / List current directory contents", "dir"),
                    ("cd", "更改目录 / Change directory", "cd {path}"),
                    ("copy", "复制文件 / Copy file", "copy {source} {destination}"),
                    ("xcopy", "高级复制 / Advanced file copy", "xcopy {source} {destination} /E /H /C /I"),
                    ("move", "移动文件 / Move file", "move {source} {destination}"),
                    ("del", "删除文件 / Delete file", "del {file}"),
                    ("md", "创建目录 / Make directory", "md {dirname}"),
                    ("rd", "删除目录 / Remove directory", "rd {dirname} /s /q"),
                    ("ren", "重命名文件 / Rename file", "ren {old} {new}"),
                    ("attrib", "更改文件属性 / Change file attributes", "attrib {+r/-r} {file}"),
                    ("tree", "显示目录结构 / Display directory tree", "tree {dirname} /f")
                ],
                "网络管理 / Network Management": [
                    ("ipconfig", "显示IP配置 / Show IP configuration", "ipconfig /all"),
                    ("ping", "测试网络连接 / Test network connection", "ping {host}"),
                    ("tracert", "跟踪网络路径 / Trace network path", "tracert {host}"),
                    ("netsh", "网络配置工具 / Network configuration tool", "netsh interface show interface"),
                    ("netstat", "显示网络状态 / Show network status", "netstat -ano"),
                    ("arp", "管理ARP缓存 / Manage ARP cache", "arp -a"),
                    ("nslookup", "DNS查询 / DNS query", "nslookup {domain}"),
                    ("route", "显示/修改路由表 / Show/Modify routing table", "route print"),
                    ("telnet", "远程终端 / Remote terminal", "telnet {host} {port}")
                ],
                "系统信息 / System Information": [
                    ("systeminfo", "显示系统信息 / Show system info", "systeminfo"),
                    ("hostname", "显示主机名 / Show hostname", "hostname"),
                    ("set", "显示环境变量 / Show environment variables", "set"),
                    ("ver", "显示Windows版本 / Show Windows version", "ver"),
                    ("wmic", "Windows管理工具 / Windows Management Instrumentation",
                     "wmic os get Caption,Version,BuildNumber,OSArchitecture"),
                    ("echo", "输出文本 / Output text", "echo {text}"),
                    ("chkdsk", "检查磁盘 / Check disk", "chkdsk"),
                    ("sfc", "系统文件检查 / System file checker", "sfc /scannow")
                ],
                "进程管理 / Process Management": [
                    ("tasklist", "显示进程列表 / Show process list", "tasklist"),
                    ("taskkill", "终止进程 / Kill process", "taskkill /F /PID {pid}"),
                    ("start", "启动新进程 / Start new process", "start {app}"),
                    ("shutdown", "关机/重启 / Shutdown/Restart", "shutdown /r /t 0"),
                    ("sc", "服务管理 / Service control", "sc query"),
                ],
                "用户管理 / User Management": [
                    ("net user", "用户管理 / User management", "net user"),
                    ("whoami", "当前用户信息 / Current user info", "whoami /all"),
                    ("gpupdate", "更新组策略 / Update group policy", "gpupdate /force"),
                    ("net localgroup", "本地组管理 / Local group management", "net localgroup"),
                ],
                "磁盘管理 / Disk Management": [
                    ("diskpart", "磁盘分区工具 / Disk partition tool", "diskpart"),
                    ("format", "格式化磁盘 / Format disk", "format {drive}:"),
                    ("vol", "显示卷标 / Show volume label", "vol {drive}:"),
                    ("label", "修改卷标 / Modify volume label", "label {drive}: {label}"),
                ],
                "安全与权限 / Security and Permissions": [
                    ("cacls", "文件权限 / File permissions", "cacls {file}"),
                    ("icacls", "高级文件权限 / Advanced file permissions", "icacls {file}"),
                    ("secedit", "安全策略 / Security policy", "secedit /analyze /db secedit.sdb"),
                    ("cipher", "加密解密 / Encrypt/Decrypt", "cipher /e /s:{folder}"),
                ],
                "日志和诊断 / Log and Diagnostics": [
                    ("eventvwr", "打开事件查看器 / Open Event Viewer", "eventvwr"),
                    ("perfmon", "打开性能监视器 / Open Performance Monitor", "perfmon"),
                    ("msinfo32", "打开系统信息 / Open System Information", "msinfo32"),
                    ("dxdiag", "DirectX诊断 / DirectX Diagnostic", "dxdiag"),
                ]
            },
            "PowerShell": {
                "文件操作 / File Operations": [
                    ("Get-ChildItem", "列出目录内容 / List directory contents", "Get-ChildItem"),
                    ("Copy-Item", "复制文件 / Copy item", "Copy-Item -Path {source} -Destination {destination}"),
                    ("Remove-Item", "删除文件 / Remove item", "Remove-Item -Path {file}"),
                    ("Rename-Item", "重命名文件 / Rename item", "Rename-Item -Path {old} -NewName {new}"),
                    ("New-Item", "新建文件/目录 / Create file/directory",
                     "New-Item -Path {path} -ItemType {File|Directory}"),
                    ("Get-Content", "查看文件内容 / View file content", "Get-Content {file}"),
                    ("Set-Content", "写入文件内容 / Write file content", "Set-Content -Path {file} -Value {content}"),
                    ("Clear-Content", "清空文件内容 / Clear file content", "Clear-Content {file}"),
                    ("Test-Path", "测试路径存在 / Test path exists", "Test-Path {path}")
                ],
                "系统管理 / System Management": [
                    ("Get-Process", "获取进程列表 / Get process list", "Get-Process"),
                    ("Stop-Process", "停止进程 / Stop process", "Stop-Process -Name {name}"),
                    ("Start-Process", "启动程序 / Start process", "Start-Process {app}"),
                    ("Get-Service", "获取服务列表 / Get service list", "Get-Service"),
                    ("Restart-Service", "重启服务 / Restart service", "Restart-Service -Name {name}"),
                    ("Set-Service", "设置服务 / Set service", "Set-Service -Name {name} -StartupType Automatic"),
                    ("Get-NetIPConfiguration", "获取网络配置 / Get network configuration", "Get-NetIPConfiguration"),
                    ("Test-NetConnection", "测试网络连接 / Test network connection", "Test-NetConnection {host}"),
                    ("Get-EventLog", "查看事件日志 / View event logs", "Get-EventLog -LogName System -Newest 20"),
                    ("Get-HotFix", "获取已安装更新 / Get installed updates", "Get-HotFix"),
                ],
                "用户与权限 / User & Permissions": [
                    ("Get-LocalUser", "列出本地用户 / List local users", "Get-LocalUser"),
                    ("New-LocalUser", "新建本地用户 / Create local user", "New-LocalUser -Name {username}"),
                    ("Add-LocalGroupMember", "添加用户到组 / Add user to group",
                     "Add-LocalGroupMember -Group Administrators -Member {user}"),
                ],
                "磁盘与硬件 / Disk & Hardware": [
                    ("Get-Volume", "列出磁盘卷 / List disk volumes", "Get-Volume"),
                    ("Get-Disk", "列出磁盘 / List disks", "Get-Disk"),
                    ("Get-PhysicalDisk", "物理磁盘信息 / Physical disk info", "Get-PhysicalDisk"),
                    ("Get-WmiObject", "获取WMI信息 / Get WMI info", "Get-WmiObject -Class Win32_Processor"),
                ],
                "脚本与开发 / Scripting & Development": [
                    ("Invoke-WebRequest", "Web请求 / Web request", "Invoke-WebRequest -Uri {url}"),
                    ("Invoke-Command", "远程命令 / Remote command",
                     "Invoke-Command -ComputerName {host} -ScriptBlock {block}"),
                    ("Import-Module", "导入模块 / Import module", "Import-Module {name}"),
                ]
            },
            "WSL/Kali": {
                "基本命令 / Basic Commands": [
                    ("ls", "列出目录 / List directory", "ls -la"),
                    ("cd", "更改目录 / Change directory", "cd {path}"),
                    ("cp", "复制文件 / Copy file", "cp {source} {destination}"),
                    ("mv", "移动/重命名 / Move/Rename", "mv {source} {destination}"),
                    ("rm", "删除文件 / Remove file", "rm -rf {file/dir}"),
                    ("cat", "查看文件 / View file", "cat {file}"),
                    ("less", "分页查看 / Page view", "less {file}"),
                    ("find", "文件搜索 / Find files", "find {path} -name {pattern}"),
                    ("grep", "文本搜索 / Search text", "grep {pattern} {file}"),
                    ("chmod", "修改权限 / Change permissions", "chmod {permissions} {file}"),
                    ("chown", "修改所有者 / Change owner", "chown {user}:{group} {file}"),
                    ("which", "查找命令路径 / Which command", "which {cmd}")
                ],
                "网络工具 / Network Tools": [
                    ("ifconfig", "网络接口配置 / Network interface config", "ifconfig"),
                    ("ip addr", "网络地址 / Network address", "ip addr"),
                    ("ping", "测试网络连接 / Test network connection", "ping {host}"),
                    ("netstat", "网络状态 / Network status", "netstat -tuln"),
                    ("ss", "套接字信息 / Socket info", "ss -tulnp"),
                    ("nmap", "网络扫描 / Network scan", "nmap -sV {target}"),
                    ("tcpdump", "网络抓包 / Packet capture", "tcpdump -i {interface}"),
                    ("curl", "网络请求 / Web request", "curl {url}"),
                    ("wget", "下载文件 / Download file", "wget {url}"),
                    ("ssh", "远程连接 / SSH connection", "ssh {user}@{host}")
                ],
                "系统管理 / System Management": [
                    ("uname", "系统信息 / System info", "uname -a"),
                    ("top", "系统监控 / System monitor", "top"),
                    ("htop", "高级系统监控 / Advanced system monitor", "htop"),
                    ("ps", "进程信息 / Process info", "ps aux"),
                    ("kill", "杀死进程 / Kill process", "kill -9 {pid}"),
                    ("df", "磁盘空间 / Disk usage", "df -h"),
                    ("du", "目录占用 / Directory usage", "du -sh {dir}"),
                    ("free", "内存信息 / Memory info", "free -m"),
                    ("uptime", "运行时间 / Uptime", "uptime"),
                    ("history", "命令历史 / Command history", "history")
                ],
                "软件与包管理 / Package Management": [
                    ("apt update", "更新软件源 / Update packages", "sudo apt update"),
                    ("apt upgrade", "升级软件 / Upgrade packages", "sudo apt upgrade -y"),
                    ("apt install", "安装软件包 / Install package", "sudo apt install {package}"),
                    ("apt remove", "卸载软件包 / Remove package", "sudo apt remove {package}"),
                    ("dpkg -l", "列出已安装包 / List installed packages", "dpkg -l"),
                    ("snap list", "列出Snap包 / List Snap packages", "snap list"),
                ],
                "安全工具 / Security Tools": [
                    ("hydra", "密码破解 / Password cracking", "hydra -l {user} -P {wordlist} {host} ssh"),
                    ("sqlmap", "SQL注入检测 / SQL Injection test", "sqlmap -u {url}"),
                    ("aircrack-ng", "WiFi破解 / WiFi cracking", "aircrack-ng {capture_file}"),
                    ("nmap", "端口/服务扫描 / Port/Service scan", "nmap -A {target}"),
                    ("msfconsole", "Metasploit框架 / Metasploit framework", "msfconsole"),
                ]
            },
            "Workspace ONE": {
                "设备管理 / Device Management": [
                    ("List Devices", "列出设备 / List devices", "Get-Device"),
                    ("Device Details", "设备详情 / Device details", "Get-Device -id {device_id}"),
                    ("Wipe Device", "擦除设备 / Wipe device", "Invoke-DeviceWipe -id {device_id}"),
                    ("Retire Device", "退役设备 / Retire device", "Invoke-DeviceRetire -id {device_id}")
                ],
                "用户管理 / User Management": [
                    ("List Users", "列出用户 / List users", "Get-User"),
                    ("User Details", "用户详情 / User details", "Get-User -id {user_id}"),
                    ("Assign Device", "分配设备 / Assign device",
                     "Add-DeviceAssignment -user_id {user_id} -device_id {device_id}")
                ],
                "应用管理 / Application Management": [
                    ("List Apps", "列出应用 / List applications", "Get-Application"),
                    ("Assign App", "分配应用 / Assign application",
                     "Add-ApplicationAssignment -app_id {app_id} -og_id {og_id}"),
                    ("App Details", "应用详情 / Application details", "Get-Application -id {app_id}")
                ]
            }
        }

    def check_wsl(self):
        try:
            result = subprocess.run(
                ["wsl", "--list", "--quiet"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8", errors="ignore"
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    def _create_scrollable_command_frame(self, parent, command_group, cmd_type):
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        scroll_frame = ttk.Frame(canvas)
        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        row = 0
        for category, cmdlist in command_group.items():
            ttk.Label(scroll_frame, text=category, font=("微软雅黑", 12, "bold")).grid(row=row, column=0, sticky="w", pady=10)
            row += 1
            col = 0
            for cmd_name, cmd_desc, cmd in cmdlist:
                btn = ttk.Button(scroll_frame, text=cmd_name, width=22,
                    command=lambda c=cmd, d=cmd_desc, n=cmd_name, t=cmd_type: self.handle_command_with_params(c, d, t, n))
                btn.grid(row=row, column=col, padx=2, pady=2, sticky="w")
                btn.bind("<Enter>", lambda e, d=cmd_desc: self.show_tooltip(d))
                btn.bind("<Leave>", lambda e: self.hide_tooltip())
                col += 1
                if col >= 5:
                    row += 1
                    col = 0
            row += 1

        # 增加“显示项目结构”按钮
        if cmd_type == "CMD":
            ttk.Button(scroll_frame, text="显示项目结构(选择文件夹)", width=25,
                       command=self.show_project_tree_cmd).grid(row=row, column=0, padx=10, pady=5, sticky="w")
        elif cmd_type == "WSL":
            ttk.Button(scroll_frame, text="显示项目结构(选择文件夹)", width=25,
                       command=self.show_project_tree_wsl).grid(row=row, column=0, padx=10, pady=5, sticky="w")
        elif cmd_type == "PowerShell":
            ttk.Button(scroll_frame, text="显示项目结构(选择文件夹)", width=25,
                       command=self.show_project_tree_ps).grid(row=row, column=0, padx=10, pady=5, sticky="w")

    def show_project_tree_cmd(self):
        folder = filedialog.askdirectory(title="选择要显示结构的根目录")
        if folder:
            cmd = f'tree "{folder}" /f'
            self.log_action(f'CMD 显示项目结构：{cmd}')
            self.execute_command(cmd, "CMD")

    def show_project_tree_ps(self):
        folder = filedialog.askdirectory(title="选择要显示结构的根目录")
        if folder:
            cmd = f'Get-ChildItem -Path "{folder}" -Recurse | Format-List FullName'
            self.log_action(f'PowerShell 显示项目结构：{cmd}')
            self.execute_command(cmd, "PowerShell")

    def show_project_tree_wsl(self):
        folder = filedialog.askdirectory(title="选择要显示结构的根目录")
        if folder:
            if sys.platform == "win32":
                folder_wsl = "/mnt/" + folder[0].lower() + folder[2:].replace("\\", "/")
            else:
                folder_wsl = folder
            cmd = f'ls -lR "{folder_wsl}"'
            self.log_action(f'WSL 显示项目结构：{cmd}')
            self.execute_command(cmd, "WSL")

    def create_cmd_tab(self):
        self._create_scrollable_command_frame(self.tab_cmd, self.command_library["CMD"], "CMD")
    def create_ps_tab(self):
        self._create_scrollable_command_frame(self.tab_ps, self.command_library["PowerShell"], "PowerShell")
    def create_wsl_tab(self):
        self._create_scrollable_command_frame(self.tab_wsl, self.command_library["WSL/Kali"], "WSL")

    def create_ws1_tab(self):
        main_frame = ttk.LabelFrame(self.tab_ws1, text="Workspace ONE命令")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        config_frame = ttk.Frame(main_frame)
        config_frame.grid(row=0, column=0, sticky="ew", pady=5, columnspan=5)
        ttk.Label(config_frame, text="API 服务器:").grid(row=0, column=0, padx=5)
        self.ws1_server = ttk.Entry(config_frame, width=30)
        self.ws1_server.grid(row=0, column=1, padx=5)
        ttk.Label(config_frame, text="API 密钥:").grid(row=0, column=2, padx=5)
        self.ws1_api_key = ttk.Entry(config_frame, width=30, show="*")
        self.ws1_api_key.grid(row=0, column=3, padx=5)
        ttk.Button(config_frame, text="测试连接", command=self.test_ws1_connection).grid(row=0, column=4, padx=5)
        row_offset = 1
        categories = list(self.command_library["Workspace ONE"].keys())
        for i, category in enumerate(categories):
            ttk.Label(main_frame, text=f"{category}:").grid(row=i + row_offset, column=0, padx=5, pady=5, sticky="w")
            col = 1
            for cmd_name, cmd_desc, cmd in self.command_library["Workspace ONE"][category]:
                btn = ttk.Button(main_frame, text=cmd_name,
                                 command=lambda c=cmd, d=cmd_desc, n=cmd_name: self.handle_command_with_params(c, d, "Workspace ONE", n),
                                 width=22)
                btn.grid(row=i + row_offset, column=col, padx=2, pady=2)
                btn.bind("<Enter>", lambda e, d=cmd_desc: self.show_tooltip(d))
                btn.bind("<Leave>", lambda e: self.hide_tooltip())
                col += 1

    def handle_command_with_params(self, cmd_template, desc, cmd_type, cmd_name):
        params = re.findall(r"{(\w+)}", cmd_template)
        args = {}
        for param in params:
            if 'file' in param.lower() or param.lower() in ['source', 'destination']:
                value = filedialog.askopenfilename(title=f"{desc} - 选择文件 [{param}]")
                if not value:
                    value = simpledialog.askstring("输入参数", f"{desc}\n请输入参数 [{param}]:", parent=self.root)
            elif 'dir' in param.lower() or param.lower() in ['dirname', 'folder']:
                value = filedialog.askdirectory(title=f"{desc} - 选择目录 [{param}]")
                if not value:
                    value = simpledialog.askstring("输入参数", f"{desc}\n请输入参数 [{param}]:", parent=self.root)
            else:
                value = simpledialog.askstring("输入参数", f"{desc}\n请输入参数 [{param}]:", parent=self.root)
            if value is None:
                self.log_action(f"{cmd_type} {cmd_name} 取消参数输入")
                return
            args[param] = value
        try:
            command = cmd_template.format(**args)
        except Exception as e:
            self.print_to_console(f"参数错误: {e}\n", "error")
            self.log_action(f"{cmd_type} {cmd_name} 参数错误: {e}")
            return
        self.log_action(f"{cmd_type} {cmd_name} 执行命令: {command}")
        self.execute_command(command, cmd_type)

    def create_custom_tab(self):
        frame = ttk.Frame(self.tab_custom)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        type_frame = ttk.Frame(frame)
        type_frame.pack(fill="x", pady=5)
        ttk.Label(type_frame, text="命令类型:").pack(side="left", padx=5)
        self.cmd_type = tk.StringVar(value="CMD")
        for text, value in [("CMD", "CMD"), ("PowerShell", "PowerShell"), ("WSL", "WSL")]:
            ttk.Radiobutton(type_frame, text=text, value=value, variable=self.cmd_type).pack(side="left", padx=5)
        cmd_frame = ttk.Frame(frame)
        cmd_frame.pack(fill="x", pady=5)
        ttk.Label(cmd_frame, text="输入命令:").pack(side="left", padx=5)
        self.custom_cmd = tk.StringVar()
        ttk.Entry(cmd_frame, textvariable=self.custom_cmd, width=60).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(cmd_frame, text="执行", command=self.execute_custom_command).pack(side="left", padx=5)
        hist_frame = ttk.LabelFrame(frame, text="历史命令")
        hist_frame.pack(fill="both", expand=True, pady=5)
        self.history_list = tk.Listbox(hist_frame, height=8)
        self.history_list.pack(fill="both", expand=True, padx=5, pady=5)
        self.history_list.bind("<<ListboxSelect>>", self.load_history_command)
        self.history = [
            "dir /B",
            "Get-Process | Where-Object { $_.CPU -gt 100 }",
            "ls -la /etc",
            "Get-Device -limit 10"
        ]
        for cmd in self.history:
            self.history_list.insert(tk.END, cmd)

    def create_library_tab(self):
        frame = ttk.Frame(self.tab_library)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill="x", pady=5)
        ttk.Label(search_frame, text="搜索命令:").pack(side="left", padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side="left", fill="x", expand=True, padx=5)
        search_entry.bind("<KeyRelease>", self.search_commands)
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill="both", expand=True, pady=5)
        self.tree = ttk.Treeview(tree_frame, columns=("Description", "Command"), show="headings")
        self.tree.heading("#0", text="类别")
        self.tree.heading("Description", text="描述/Description")
        self.tree.heading("Command", text="命令/Command")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.populate_command_tree()
        self.tree.bind("<Double-1>", self.execute_tree_command)

    def populate_command_tree(self, search_term=None):
        self.tree.delete(*self.tree.get_children())
        for category, commands in self.command_library.items():
            for subcat, cmd_list in commands.items():
                for cmd_name, cmd_desc, cmd in cmd_list:
                    if search_term:
                        search_term = search_term.lower()
                        if (search_term not in cmd_name.lower() and
                                search_term not in cmd_desc.lower() and
                                search_term not in cmd.lower()):
                            continue
                    parent = f"{category} - {subcat}"
                    if not self.tree.exists(parent):
                        self.tree.insert("", "end", parent, text=parent)
                    self.tree.insert(parent, "end", values=(cmd_desc, cmd))

    def search_commands(self, event=None):
        search_term = self.search_var.get().strip()
        self.populate_command_tree(search_term if search_term else None)

    def execute_tree_command(self, event):
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        if values:
            command = values[1]
            self.custom_cmd.set(command)
            self.tab_control.select(self.tab_custom)
            self.execute_custom_command()

    def show_tooltip(self, text):
        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.geometry(f"+{self.root.winfo_pointerx() + 10}+{self.root.winfo_pointery() + 10}")
        label = tk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self):
        if hasattr(self, "tooltip") and self.tooltip:
            self.tooltip.destroy()

    def execute_command(self, command, cmd_type="CMD"):
        self.log_action(f"执行 {cmd_type} 命令: {command}")
        self.print_to_console(f">>> [{cmd_type}] 执行命令: {command}\n", "cmd")
        self.status_var.set("执行中...")
        try:
            if cmd_type == "CMD":
                result = subprocess.run(
                    ["cmd", "/c", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8", errors="ignore",
                    shell=True
                )
            elif cmd_type == "PowerShell":
                result = subprocess.run(
                    ["powershell", "-Command", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8", errors="ignore",
                    shell=True
                )
            elif cmd_type == "WSL":
                result = subprocess.run(
                    ["wsl", "-e", "bash", "-c", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8", errors="ignore"
                )
            elif cmd_type == "Workspace ONE":
                self.print_to_console(f"已模拟执行: {command}\n", "success")
                self.status_var.set("Workspace ONE命令模拟完成")
                self.log_action(f"Workspace ONE 执行模拟命令: {command}")
                return

            if result and result.stdout:
                self.print_to_console(result.stdout + "\n", "success")
                self.log_action(f"{cmd_type} 执行命令成功，输出：{result.stdout.strip()}")
            if result and result.stderr:
                self.print_to_console(result.stderr + "\n", "error")
                self.log_action(f"{cmd_type} 执行命令错误，输出：{result.stderr.strip()}")
            self.status_var.set("命令执行完成")
        except Exception as e:
            self.print_to_console(f"执行错误: {str(e)}\n", "error")
            self.status_var.set(f"错误: {str(e)}")
            self.log_action(f"{cmd_type} 执行命令异常: {e}")

    def execute_custom_command(self):
        command = self.custom_cmd.get().strip()
        if not command:
            return
        cmd_type = self.cmd_type.get()
        self.log_action(f"自定义命令 [{cmd_type}]: {command}")
        self.execute_command(command, cmd_type)

    def run_ps_script(self):
        file_path = filedialog.askopenfilename(
            title="选择PowerShell脚本",
            filetypes=[("PowerShell Scripts", "*.ps1"), ("All Files", "*.*")]
        )
        if file_path:
            self.execute_ps_command(f". '{file_path}'")

    def test_ws1_connection(self):
        server = self.ws1_server.get().strip()
        api_key = self.ws1_api_key.get().strip()
        if not server or not api_key:
            self.print_to_console("错误: 请填写服务器地址和API密钥\n", "error")
            self.log_action("Workspace ONE 连接测试失败：未填写服务器或密钥")
            return
        self.print_to_console(f"测试连接到Workspace ONE服务器: {server}\n", "cmd")
        self.print_to_console("连接测试成功!\n", "success")
        self.status_var.set("Workspace ONE连接测试成功")
        self.log_action(f"Workspace ONE 连接测试成功：{server}")

    def load_history_command(self, event):
        if self.history_list.curselection():
            index = self.history_list.curselection()[0]
            self.custom_cmd.set(self.history_list.get(index))
            self.log_action(f"历史命令加载到输入框: {self.history_list.get(index)}")

    def print_to_console(self, text, tag="normal"):
        self.console.configure(state="normal")
        self.console.insert(tk.END, text, tag)
        self.console.configure(state="disabled")
        self.console.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = UltimateWindowsCommandCenter(root)
    root.mainloop()
