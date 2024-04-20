import traceback
import re
import os
from collections import Counter
import sys
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import threading
import schedule
import time
import requests
from Levenshtein import distance
import math
import base64
import subprocess
from lxml import etree
import shutil
PE_STRINGS_FILE = "./strings.xml"
stringScores = {}
ANALYZE_EXTENSIONS = [".asp", ".vbs", ".ps", ".ps1", ".tmp", ".bas", ".bat", ".cmd", ".com", ".cpl",
                       ".crt", ".dll", ".exe", ".msc", ".scr", ".sys", ".vb", ".vbe", ".vbs", ".wsc",
                       ".wsf", ".wsh", ".input", ".war", ".jsp", ".php", ".asp", ".aspx", ".psd1", ".psm1", ".py"]
def extract_base64_strings(data):
    base64_strings = []
    for bs in re.findall(b"(?:[A-Za-z0-9+/]{4}){5,}", data):
        try:
            base64_string = base64.b64decode(bs).decode("latin-1")
            if is_ascii_string(base64_string):
                base64_strings.append(base64_string)
        except (ValueError, UnicodeDecodeError):
            pass
    return base64_strings

def extract_hex_strings(data):
    hex_strings = []
    for hs in re.findall(b"(?:[0-9A-Fa-f]{2}){10,}", data):
        try:
            hex_string = bytes.fromhex(hs.decode()).decode("latin-1")
            if is_ascii_string(hex_string):
                hex_strings.append(hex_string)
        except (ValueError, UnicodeDecodeError):
            pass
    return hex_strings

def is_ascii_string(string, padding_allowed=False):
    for b in string:
        if padding_allowed:
            if not ((ord(b) < 127 and ord(b) > 31) or ord(b) == 0):
                return 0
        else:
            if not (ord(b) < 127 and ord(b) > 31):
                return 0
    return 1

def extract_strings(fileData) -> list[str]:
    cleaned_strings = []
    try:
        ascii_strings = extract_ascii_strings(fileData)
        wide_strings = extract_wide_strings(fileData)
        hex_strings = extract_hex_strings(fileData)
        base64_strings = extract_base64_strings(fileData)
        
        # Extract strings using Regex
        regex_pattern = br"[\x1f-\x7e]{6,}"
        regex_strings = re.findall(regex_pattern, fileData)
        
        # Combine all strings
        strings = ascii_strings + wide_strings + hex_strings + base64_strings + [s.decode("latin-1", errors="ignore") for s in regex_strings]
        strings = list(set(strings))

        for string in strings:
            if len(string) > 0:
                string = string.replace("\\", "\\\\").replace('"', '\\"')
                cleaned_strings.append(string)
    except Exception as e:
        print(f"Error extracting strings: {e}")

    return cleaned_strings

def extract_ascii_strings(data):
    ascii_strings = []
    for string in re.findall(b"[\x20-\x7E]{5,}", data):
        try:
            ascii_string = string.decode("ascii")
            ascii_strings.append(ascii_string)
        except UnicodeDecodeError:
            pass
    return ascii_strings

def get_string(file_path):
    try:
        with open(file_path, 'rb') as f:
            fileData = f.read()
    except Exception as e:
        print("Cannot read file - skipping %s" % file_path)
        return []

    return extract_strings(fileData)

def filter_string(strings):
    filtered_strings = []
    
    # 移除非法字符
    strings = [re.sub(r"[^\x20-\x7E]", "", string) for string in strings]
    
    # 過濾相似的字符串
    strings = filter_similar_strings(strings, threshold=0.8)
    
    # 過濾隨機性較高的字符串
    strings = filter_high_entropy_strings(strings, threshold=3.5)
    
    # 根據字符串的長度和複雜度進行綜合評分和排序
    strings = sort_strings_by_score(strings)
    
    # 加入額外的特徵字串評分
    strings = score_extra_features(strings)
    
    result = []
    for i, string in enumerate(strings[:20], start=1):
        result.append(f'        $s{i} = "{string}"')
    
    return "\n".join(result)

def get_size(file_path):
    size = os.stat(file_path).st_size
    size = int(size / 1024) + 5
    return size

def get_n_them(strings):
    n = len(strings)
    if n <= 4:
        n_them = "all of them"
    elif n <= 8:
        n_them = "8 of them"
    else:
        n_them = "4 of them"
    return n_them

def write_yara(out_yar, rule):
    # open
    yara_rule="import ""pe"""
    yara_rule+=rule
    if out_yar:
        try:
            fh = open(out_yar, 'w')
        except Exception as e:
            traceback.print_exc()
    # write rule
    try:
        if out_yar:
            with open(out_yar,"a+") as fh:
                fh.write(yara_rule)
    except Exception as e:
        traceback.print_exc()

    # close file
    if out_yar:
        try:
            fh.close()
        except Exception as e:
            traceback.print_exc()


def uploadfolder(malwarefolder, out_yara):
    # 讀取每個資料夾的每個惡意軟體
    rules = ""
    total_files = sum(len(files) for _, _, files in os.walk(malwarefolder))
    processed_files = 0

    for root, dirs, files in os.walk(malwarefolder):
        for file in files:
            malware_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1].lower()

            # 檢查檔案副檔名是否在 ANALYZE_EXTENSIONS 中
            if file_extension not in ANALYZE_EXTENSIONS:
                print(f"Skipping unsupported file type: {malware_path}")
                continue

            try:
                strings = get_string(malware_path)
                filename = re.sub("[.:'""\- \\\\]", "_", os.path.basename(malware_path))
                filename = re.sub(r"\\d", lambda match: f"NB{chr(ord('A') + int(match.group()))}", filename, count=3)
                filename = re.sub("[0123456789]", "", filename)
                filestr = filter_string(strings)
                filesize = f"filesize < {str(get_size(malware_path))}KB"
                filethem = get_n_them(strings)

                rule = f"""
rule {filename} {{
strings:
{filestr}
condition:
    uint16(0) == 0x5a4d and {filesize} and
    {filethem}
}}
    """
                rules+=(rule)
                processed_files += 1
            except Exception as e:
                print(f"Error processing file: {malware_path}")
                traceback.print_exc()

    # 將所有規則寫入 YARA 文件
    write_yara(out_yara, rules)

def spilt(all_yar):
    folder_yar="ALL yara rules"
    with open(all_yar, 'r') as file:
        content = file.read()

    rules = content.split('rule ')

    os.makedirs(folder_yar, exist_ok=True)

    for i, rule in enumerate(rules[1:], start=1):
        rule_name = rule.split(' ')[0]
        filename = folder_yar+f'/rule_{i:02d}_{rule_name}.yar'
        with open(filename, 'w',encoding="cp950") as file:
            file.write(f'rule {rule}')

def scan_extract_strings(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
        strings = re.findall(br"[\x20-\x7E]{4,}", content)
        return [s.decode("ascii") for s in strings]

def scan_match_strings(file_strings, rule_strings):
    matches = []
    for rule_string in rule_strings:
        if rule_string in file_strings:
            matches.append(rule_string)
    return matches

def scan_parse_yara_rule(rule_path):
    with open(rule_path, "r") as f:
        content = f.read()
        rule_name = re.search(r"rule\s+(\w+)", content).group(1)
        strings = re.findall(r"\$\w+\s+=\s+\"(.+?)\"", content)
        return rule_name, strings

def scan_file(file_path, rule_path):
    file_strings = scan_extract_strings(file_path)
    rule_name, rule_strings = scan_parse_yara_rule(rule_path)
    matches = scan_match_strings(file_strings, rule_strings)
    if matches:
        return rule_name, matches
    return None

def scan_malware_folder(malware_dir, rules_dir):
    report = []
    matched_files = {}
    total_files = sum(len(files) for _, _, files in os.walk(malware_dir))
    processed_files = 0

    with open("out_stdout.txt", "w") as stdout_file:
        for root, dirs, files in os.walk(malware_dir):
            for file in files:
                processed_files += 1
                file_path = os.path.join(root, file)

                # 生成與 uploadfolder 函數相同的 filename
                filename = re.sub("[.:'""\- \\\\]", "_", os.path.basename(file_path))
                filename = re.sub(r"\\d", lambda match: f"NB{chr(ord('A') + int(match.group()))}", filename, count=3)
                filename = re.sub("[0123456789]", "", filename)

                for rule_file in os.listdir(rules_dir):
                    if rule_file.endswith(".yar"):
                        rule_path = os.path.join(rules_dir, rule_file)

                        # 使用 subprocess 調用 YARA 進行掃描
                        command = f"yara64 \"{rule_path}\" \"{file_path}\""
                        output = subprocess.run(command, capture_output=True, text=True, shell=True)
                        print(output)

                        # 將 output.stdout 寫入 out_stdout.txt 文件
                        stdout_file.write(output.stdout + "\n")

                        if output.returncode == 0 and output.stdout.strip():
                            # 檢查命令列輸出是否包含 "filename" "file_path" 的格式
                            if filename in output.stdout:
                                if file_path not in matched_files:
                                    matched_files[file_path] = []
                                matched_files[file_path].append((rule_file, command))

    for file_path, matched_rules in matched_files.items():
        report.append(f"檔案: {file_path}")
        report.append("被以下規則掃描到:")
        for rule, command in matched_rules:
            report.append(f"- 規則: {rule}")
            report.append(f"  命令: {command}")
        report.append("")

    summary = f"\n總結:\n被掃描到的惡意程式: {len(matched_files)}\n總共掃描的程式: {total_files}"
    report.append(summary)
    return report, summary

def scan_main(malware_dir,rules_dir):
    # 指定惡意軟體和YARA規則的資料夾路徑
    malware_dir = malware_dir
    rules_dir = rules_dir

    # 掃描惡意軟體資料夾並生成報告
    report,summary = scan_malware_folder(malware_dir, rules_dir)

    # 將報告寫入report.txt文件
    with open("report.txt", "w",encoding="utf-8") as f:
        f.write("\n".join(report))

    return summary

def yargen():
    try:
        malware_path=entry_malware_folder.get()
        out_yar="all_yara.yar"
        uploadfolder(malware_path,out_yar)
        spilt(out_yar)
        messagebox.showinfo("完成", "自動分析完成!")
    except Exception as e:
        messagebox.showerror("錯誤", f"自動分析過程發生錯誤: {str(e)}")

def auto_scan(malware_path,is_scan=False):
    if is_scan:
        scan_main(malware_path,"ALL yara rules")

def browse_malware_folder():
    folder_path = filedialog.askdirectory()
    entry_malware_folder.delete(0, tk.END)
    entry_malware_folder.insert(tk.END, folder_path)

def send_line_notify(message):
    line_notify_token = ''  # 請替換為你的 Line Notify Token
    line_notify_api = 'https://notify-api.line.me/api/notify'
    headers = {'Authorization': f'Bearer {line_notify_token}'}
    data = {'message': message}
    response = requests.post(line_notify_api, headers=headers, data=data)
    return response.status_code

def scan_yara_rules():
    malware_folder = entry_malware_folder.get()
    rule_folder = "ALL yara rules"
    if not malware_folder or not rule_folder:
        messagebox.showerror("錯誤", "找不到惡意樣本資料夾和YARA 規則資料夾。")
        return

    try:
        result = scan_main(malware_folder, rule_folder)
        print("result:", result)
        send_line_notify(result)
        messagebox.showinfo("偵測結果", "偵測完成!")
    except Exception as e:
        messagebox.showerror("錯誤", f"掃描過程發生錯誤: {str(e)}")

def start_immediate_scan():
    scan_thread = threading.Thread(target=scan_yara_rules)
    scan_thread.daemon = True
    scan_thread.start()

def start_scheduled_scan():
    scan_time = entry_time.get()
    scan_day = var_day.get()

    if scan_day == "每天":
        schedule.every().day.at(scan_time).do(scan_yara_rules)
    else:
        messagebox.showerror("錯誤", "無效的掃描日期選項。")
        return

    while True:
        schedule.run_pending()
        time.sleep(1)

def start_scan_thread():
    scan_thread = threading.Thread(target=start_scheduled_scan)
    scan_thread.daemon = True
    scan_thread.start()

def is_similar(s1, s2, threshold=0.8):
    return (len(s1) + len(s2)) != 0 and distance(s1, s2) / (len(s1) + len(s2)) <= (1 - threshold)

def filter_similar_strings(strings, threshold=0.8):
    filtered_strings = []
    for string in strings:
        if not any(is_similar(string, s, threshold) for s in filtered_strings):
            filtered_strings.append(string)
    return filtered_strings

def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def filter_high_entropy_strings(strings, threshold=3.5):
    return [string for string in strings if calculate_entropy(string) < threshold]

def score_string(string):
    length_score = min(len(string) / 10, 1)
    entropy_score = min(calculate_entropy(string) / 4, 1)
    return (length_score + entropy_score) / 2

def sort_strings_by_score(strings):
    return sorted(strings, key=score_string, reverse=True)

def initialize_pestudio_strings():
    pestudio_strings = {}

    tree = etree.parse(PE_STRINGS_FILE)

    pestudio_strings["strings"] = tree.findall(".//string")
    pestudio_strings["av"] = tree.findall(".//av")
    pestudio_strings["folder"] = tree.findall(".//folder")
    pestudio_strings["os"] = tree.findall(".//os")
    pestudio_strings["reg"] = tree.findall(".//reg")
    pestudio_strings["guid"] = tree.findall(".//guid")
    pestudio_strings["ssdl"] = tree.findall(".//ssdl")
    pestudio_strings["ext"] = tree.findall(".//ext")
    pestudio_strings["agent"] = tree.findall(".//agent")
    pestudio_strings["oid"] = tree.findall(".//oid")
    pestudio_strings["priv"] = tree.findall(".//priv")

    return pestudio_strings

def get_pestudio_score(string):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""

def score_extra_features(strings):
    for string in strings:
        pescore, pestype = get_pestudio_score(string)
        if pescore > 0:
            if string not in stringScores:
                stringScores[string] = 0
            stringScores[string] += pescore

        # Add your own extra scoring logic here
        # For example, you can score certain patterns, keywords, or characteristics

    return strings

def extract_wide_strings(data):
    wide_strings = []
    for ws in re.findall(b"(?:[\x20-\x7E]\x00){5,}", data):
        try:
            wide_string = ws.decode("utf-16le")
            if is_ascii_string(wide_string):
                wide_strings.append(wide_string)
        except UnicodeDecodeError:
            pass
    return wide_strings

def update_yara_rules():
    github_url = "https://github.com/Yara-Rules/rules"
    all_yara_rules_folder = "ALL Yara Rules"

    # 創建 "ALL Yara Rules" 資料夾(如果不存在)
    if not os.path.exists(all_yara_rules_folder):
        os.makedirs(all_yara_rules_folder)

    # 克隆 Yara-Rules 到 "ALL Yara Rules" 資料夾
    cmd = f"git clone {github_url}"
    output = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    old_folder="Yara-Rules"
    print(output)

    # 將每個資料夾中的 yar 檔案複製到 "ALL Yara Rules" 資料夾
    for root, dirs, files in os.walk(old_folder):
        for file in files:
            if file.endswith(".yar"):
                src_path = os.path.join(root, file)
                dst_path = os.path.join(all_yara_rules_folder, file)
                shutil.copy(src_path, dst_path)
                print(f"Copied {file} to {all_yara_rules_folder}")
    return


# 創建主視窗
window = tk.Tk()
window.title("YARA 規則生成器")


# 創建惡意資料夾選擇器
label_malware_folder = tk.Label(window, text="惡意樣本資料夾:")
label_malware_folder.pack()

entry_malware_folder = tk.Entry(window, width=50)
entry_malware_folder.pack()

button_browse_malware = tk.Button(window, text="選擇", command=browse_malware_folder)
button_browse_malware.pack()

# 創建生成按鈕
button_generate = tk.Button(window, text="自動分析", command=yargen)
button_generate.pack()


# 創建掃描選項
label_scan = tk.Label(window, text="掃描選項:")
label_scan.pack()

button_immediate_scan = tk.Button(window, text="更新規則", command=update_yara_rules)
button_immediate_scan.pack()

button_immediate_scan = tk.Button(window, text="立即掃描", command=start_immediate_scan)
button_immediate_scan.pack()

label_time = tk.Label(window, text="掃描時間 (HH:MM):")
label_time.pack()

entry_time = tk.Entry(window, width=10)
entry_time.insert(tk.END, "13:00")  # 預設時間為下午 1 點
entry_time.pack()

var_day = tk.StringVar(value="每天")
radio_day = tk.Radiobutton(window, text="每天", variable=var_day, value="每天")
radio_day.pack()

button_start_scan = tk.Button(window, text="定時掃描", command=start_scan_thread)
button_start_scan.pack()

# 初始化 PEStudio 字串資料庫
pestudio_strings = initialize_pestudio_strings()

# 運行主循環
window.mainloop()

# 比較穩定的版本