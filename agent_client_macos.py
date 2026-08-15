#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCTaller Diagnostics Agent v2.0 — Cliente macOS
================================================
Versión nativa para macOS (arm64/x86_64) del agente de diagnóstico remoto.

Mismo protocolo WebSocket que el cliente Windows, pero reemplaza
PowerShell/WMI por comandos nativos de macOS:
  system_profiler, sysctl, ps, top, lsof, netstat, launchctl,
  log show, diskutil, df, du, ioreg, pmset, networksetup, etc.

Compilar en macOS con PyInstaller:
    pyinstaller --onefile --windowed --name="PCTaller-Diagnostics" agent_client_macos.py

Notas:
  - El Tkinter GUI funciona de forma nativa en macOS (Python de python.org/Homebrew).
  - Los diagnósticos v2.0 (malware, radar, persistencia) están reimplementados
    sobre la pila macOS (launchd, launchctl, ps, lsof, spctl).
  - No dependemos de PowerShell: usamos /bin/sh y /usr/bin/osascript.
"""

import asyncio
import json
import os
import sys
import subprocess
import tempfile
import uuid
import queue
import shlex
import socket
from datetime import datetime, timezone
import threading

try:
    import websockets
except ImportError:
    import subprocess as _sp
    _sp.run([sys.executable, "-m", "pip", "install", "websockets"], check=True)
    import websockets

try:
    import psutil
except ImportError:
    psutil = None

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
SERVER_HOSTS = [
    "192.168.254.235",   # LAN local
    "100.105.219.40",    # Tailscale
]
SERVER_PORT = 18790

def _hostname():
    try:
        import getpass
        return socket.gethostname() or "mac"
    except Exception:
        return "mac"

AGENT_NAME = os.environ.get("HOSTNAME") or _hostname()
AGENT_USER = os.environ.get("USER") or (os.getlogin() if hasattr(os, "getlogin") else "macuser")
RECONNECT_DELAY = 5
VERSION = "2.0-macos"

# ---------------------------------------------------------------------------
# GUÍA: esta versión NO usa PowerShell. Executamos /bin/sh.
# ---------------------------------------------------------------------------
SHELL = "/bin/sh"

MAX_OUTPUT = 100000

# Modo autotest: python3 agent_client_macos.py --selftest
# Corre los diagnósticos nativos + prueba WebSocket sin GUI y sin servidor externo.
SELFTEST = "--selftest" in sys.argv


# ---------------------------------------------------------------------------
# LOGGING COLA (thread-safe para la GUI)
# ---------------------------------------------------------------------------
log_queue = queue.Queue()

def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {msg}"
    if SELFTEST:
        print(line, flush=True)
    else:
        log_queue.put(line)


# ---------------------------------------------------------------------------
# VENTANA PRINCIPAL (Tkinter en hilo separado)
# ---------------------------------------------------------------------------
class LogWindow:
    def __init__(self):
        self.root = None
        self.text = None
        self.status_var = None
        self.running = True

    def build(self):
        import tkinter as tk
        from tkinter import scrolledtext
        self.root = tk.Tk()
        self.root.title(f"PCTaller Diagnostics v2.0 — {AGENT_NAME}")
        self.root.geometry("1000x650")
        self.root.minsize(600, 400)
        self.root.configure(bg="#1e1e2e")

        info_frame = tk.Frame(self.root, bg="#1e1e2e", pady=4)
        info_frame.pack(fill=tk.X, padx=8)
        tk.Label(info_frame, text=f"🖥️  {AGENT_NAME}", font=("Menlo", 14, "bold"),
                 fg="#cdd6f4", bg="#1e1e2e").pack(side=tk.LEFT, padx=(0, 20))
        tk.Label(info_frame, text=f"👤 {AGENT_USER}", font=("Menlo", 10),
                 fg="#a6adc8", bg="#1e1e2e").pack(side=tk.LEFT, padx=(0, 20))
        tk.Label(info_frame, text=f"macOS {VERSION}", font=("Menlo", 10, "bold"),
                 fg="#fab387", bg="#1e1e2e").pack(side=tk.RIGHT, padx=8)

        sep = tk.Frame(self.root, height=2, bg="#313244")
        sep.pack(fill=tk.X, padx=8)

        text_frame = tk.Frame(self.root, bg="#1e1e2e")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 2))
        self.text = scrolledtext.ScrolledText(
            text_frame, wrap=tk.WORD, font=("Menlo", 10),
            bg="#11111b", fg="#cdd6f4", insertbackground="#cdd6f4",
            borderwidth=0, padx=10, pady=10, state=tk.DISABLED, highlightthickness=0,
        )
        self.text.pack(fill=tk.BOTH, expand=True)
        for tag, color in [("info", "#89b4fa"), ("ok", "#a6e3a1"), ("warn", "#f9e2af"),
                           ("error", "#f38ba8"), ("cmd", "#cba6f7"), ("result", "#94e2d5"),
                           ("malware", "#f38ba8"), ("radar", "#fab387"),
                           ("persist", "#f9e2af"), ("bold", "#cdd6f4")]:
            self.text.tag_config(tag, foreground=color,
                                 font=("Menlo", 10, "bold") if tag == "malware" or tag == "radar" or tag == "persist" or tag == "bold" else ("Menlo", 10))

        status_frame = tk.Frame(self.root, bg="#181825", height=28)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        self.status_var = tk.StringVar(value="⏳ Iniciando...")
        tk.Label(status_frame, textvariable=self.status_var, font=("Menlo", 9),
                 fg="#a6adc8", bg="#181825", anchor=tk.W, padx=10).pack(side=tk.LEFT, fill=tk.X)
        tk.Label(status_frame, text="PCTaller Diagnostics", font=("Menlo", 8),
                 fg="#585b70", bg="#181825", padx=10).pack(side=tk.RIGHT)

        self._poll_log_queue()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _poll_log_queue(self):
        try:
            while True:
                self._append_line(log_queue.get_nowait())
        except queue.Empty:
            pass
        if self.running and self.root:
            self.root.after(100, self._poll_log_queue)

    def _append_line(self, line):
        if not self.text:
            return
        self.text.configure(state=tk.NORMAL)
        if "[MALWARE]" in line:
            tag = "malware"
        elif "[RADAR]" in line:
            tag = "radar"
        elif "[PERSIST]" in line:
            tag = "persist"
        elif "ERROR" in line or "Fallo" in line:
            tag = "error"
        elif "[OK]" in line or "Conectado" in line:
            tag = "ok"
        elif "[>]" in line:
            tag = "cmd"
        elif "[R]" in line or "[<]" in line:
            tag = "result"
        elif "[WARN]" in line or "⚠" in line:
            tag = "warn"
        elif "[+]" in line or "Nueva" in line:
            tag = "info"
        else:
            tag = "info"
        self.text.insert(tk.END, line + "\n", (tag,))
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def update_status(self, text):
        if self.status_var:
            self.status_var.set(f"  {text}")

    def _on_close(self):
        self.running = False
        if self.root:
            self.root.destroy()
            self.root = None
        os._exit(0)

    def start(self):
        self.build()
        if self.root:
            self.root.mainloop()


window = None
if not SELFTEST:
    window = LogWindow()
    gui_thread = threading.Thread(target=window.start, daemon=True)
    gui_thread.start()
    import time
    while window.root is None:
        time.sleep(0.1)


def gui_log(kind, msg):
    prefixes = {
        "info": " [i]", "ok": " [OK]", "warn": " [WARN]", "error": " [ERROR]",
        "cmd": " [>]", "result": " [R]", "malware": " [MALWARE]",
        "radar": " [RADAR]", "persist": "[PERSIST]",
    }
    log(f"{prefixes.get(kind, ' [i]')} {msg}")
    if SELFTEST:
        return
    if kind == "ok":
        window.update_status(f"✅ {msg[:80]}")
    elif kind == "error":
        window.update_status(f"❌ {msg[:80]}")
    elif kind == "cmd":
        window.update_status(f"⚡ {msg[:80]}")
    elif kind in ("malware", "radar", "persist"):
        window.update_status(f"🔴 {msg[:80]}")


# ---------------------------------------------------------------------------
# EJECUTOR DE COMANDOS NATIVOS (sh)
# ---------------------------------------------------------------------------
async def run_sh(script, timeout=120):
    """Ejecuta un script /bin/sh y devuelve la salida."""
    try:
        proc = await asyncio.create_subprocess_exec(
            SHELL, "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/tmp",
            env={**os.environ, "LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            gui_log("error", "⏰ Comando tardó más de 120s — TIMEOUT")
            return "ERROR: TIMEOUT - El comando tardó mas de 120 segundos"
        out = stdout.decode("utf-8", errors="replace").replace("\ufffd", "")
        err = stderr.decode("utf-8", errors="replace").replace("\ufffd", "")
        if proc.returncode == 0:
            return out.strip() if out.strip() else "(OK - sin salida)"
        else:
            detail = err.strip() if err.strip() else out.strip()
            return f"ERROR (exit {proc.returncode}): {detail[:2000]}"
    except FileNotFoundError:
        gui_log("error", "SHELL no encontrado en el sistema")
        return "ERROR: /bin/sh no está disponible"
    except Exception as e:
        gui_log("error", f"Error ejecutando sh: {e}")
        return f"ERROR: {str(e)[:500]}"


async def execute_custom_shell(command):
    """Comando shell personalizado (equivalente a custom_cmd en macOS)."""
    gui_log("cmd", f"💻 Ejecutando sh: {command[:80]}")
    return await run_sh(command)


# ---------------------------------------------------------------------------
# DIAGNÓSTICOS NATIVOS macOS
# ---------------------------------------------------------------------------

# --- 1. SALUD DEL SISTEMA ---
CMD_MAC_SYSTEM_HEALTH = r'''
echo "=== DISCOS ===";
df -h | awk 'NR==1 || /^\/dev\//';
echo;
echo "=== SMART / DISCOS FISICOS ===";
diskutil list | grep -E "^\s*[0-9]|/dev/disk|disk image|Physical Volume|Media Name|Disk Size" ;
echo;
echo "=== MEMORIA ===";
sysctl -n hw.memsize | awk '{printf "Total: %.2f GB\n", $1/1073741824}';
vm_stat | awk '/Pages free/ {print "Páginas libres:", $3}';
echo;
echo "=== UPTIME / CARGA ===";
uptime;
echo;
echo "=== TOP PROCESOS CPU ===";
ps -arcwwwxo pid,%cpu,%mem,comm | head -n 12;
echo;
echo "=== TOP PROCESOS RAM ===";
ps -axmww -o pid,%mem,%cpu,comm | head -n 12;
echo;
echo "=== TAMAÑO APP + SISTEMA ===";
sw_vers;
dmesg | grep -i "restart\|panic" | tail -n 10 2>/dev/null
'''

# --- 2. HARDWARE ---
CMD_MAC_HARDWARE = r'''
echo "=== MAC MODELO ===";
system_profiler SPHardwareDataType | sed 's/^ *//' | grep -E "Model|Chip|Processor|Memory|Serial|UUID|Cores";
echo;
echo "=== GPU ===";
system_profiler SPDisplaysDataType | sed 's/^ *//' | grep -E "Chipset|Vendor|VRAM|Metal|Resolution";
echo;
echo "=== RAM ===";
sysctl -n hw.memsize | awk '{printf "Total: %.2f GB\n", $1/1073741824}';
echo;
echo "=== ALMACENAMIENTO ===";
system_profiler SPStorageDataType | sed 's/^ *//' | grep -E "Media Name|Capacity|Available|Medium Type|Protocol|SMART";
echo;
echo "=== RED ===";
networksetup -listallhardwareports;
echo "--- IPs ---";
ipconfig getifaddr en0 2>/dev/null; ipconfig getifaddr en1 2>/dev/null; ifconfig | grep "inet " | grep -v 127.0.0.1;
'''

# --- 3. TEMPERATURAS (se requiere sudo o lectura de SMC; sin ella mostramos estimación) ---
CMD_MAC_TEMPERATURES = r'''
echo "=== TEMPERATURAS (macOS) ===";
echo "Nota: la lectura directa del SMC requiere permisos de root o utilidades de terceros (p.ej. osx-cpu-temp / powermetrics con sudo).";
echo;
echo "=== CARGA TÉRMICA / CORES ===";
sysctl -n machdep.cpu.brand_string;
sysctl -n hw.ncpu | awk '{print "Cores:", $1}';
echo;
echo "=== ACTIVIDAD (top térmico aproximado) ===";
ps -arcwwwxo %cpu,comm | head -n 10;
echo;
echo "=== POWERTHERMICS (si hay sudo, descomentar) ===";
echo "sudo powermetrics --samplers smc -n1 2>/dev/null | grep -E 'CPU die|GPU die'"
'''

# --- 4. BATERÍA ---
CMD_MAC_BATTERY = r'''
echo "=== BATERÍA ===";
system_profiler SPPowerDataType | sed 's/^ *//' | grep -E "Cycle Count|Condition|Maximum Capacity|Current Capacity|Connected|Charging|Battery Installed|Full Charge Capacity";
echo;
echo "=== PMSET (salud/estado) ===";
pmset -g batt;
echo;
echo "=== ADAPTADOR / TIEMPO ESTIMADO ===";
pmset -g batt | grep -E "remaining|charging|discharging" || true;
'''

# --- 5. LICENCIAS / SISTEMA ---
CMD_MAC_LICENSES = r'''
echo "=== VERSIONES DE SISTEMA ===";
sw_vers;
echo;
echo "=== SOFTWARE INSTALADO (aplicaciones en /Applications) ===";
ls -1 /Applications | head -n 60;
echo;
echo "=== XCODE / HERRAMIENTAS ===";
xcodebuild -version 2>/dev/null || echo "Xcode tools no detectados";
echo;
echo "=== Nota: macOS no usa licencias tipo Windows/Office. Para Office 365 revisar: ===";
echo "  /Applications/Microsoft Office.app/Contents/Resources/MAU*  (detección por app)";
mdfind "kMDItemKind == 'Application' AND kMDItemDisplayName == '*Office*'" 2>/dev/null | head
'''

# --- 6. PUERTOS / CONEXIONES ---
CMD_MAC_PORTS = r'''
echo "=== PUERTOS EN ESCUCHA ===";
lsof -nP -iTCP -sTCP:LISTEN | awk 'NR==1 || $9 ~ /:\*/' | head -n 40;
echo;
echo "=== CONEXIONES ESTABLECIDAS ===";
netstat -an -p tcp | grep ESTABLISHED | head -n 30;
echo;
echo "=== PUERTOS ALTOS >1024 EN ESCUCHA ===";
lsof -nP -iTCP -sTCP:LISTEN | awk '{print $9}' | grep -oE ':[0-9]+$' | tr -d ':' | sort -n | awk '$1>1024' | uniq -c | sort -rn | head -n 25;
'''

# --- 7. SOFTWARE INSTALADO ---
CMD_MAC_INSTALLED_SOFTWARE = r'''
echo "=== APLICACIONES (Application dirs) ===";
ls -1 /Applications 2>/dev/null | wc -l | awk '{print "Apps en /Applications:", $1}';
echo;
echo "=== LISTADO /Applications ===";
ls -1 /Applications 2>/dev/null;
echo;
echo "=== Apps del usuario ===";
ls -1 ~/Applications 2>/dev/null || echo "(sin apps de usuario)";
echo;
echo "=== Homebrew (si existe) ===";
brew list --formula 2>/dev/null | head -n 40 || echo "Homebrew no instalado";
'''

# --- 8. ARCHIVOS TEMPORALES ---
CMD_MAC_TEMP_FILES = r'''
echo "=== CARPETA TEMPORAL (dónde está el agente) ===";
echo "TMPDIR=$TMPDIR";
echo;
echo "=== TAMAÑO /tmp y ~/Library/Caches ===";
du -sh /tmp 2>/dev/null;
du -sh ~/Library/Caches 2>/dev/null;
echo;
echo "=== TOP 20 ARCHIVOS GRANDES EN /tmp ===";
find /tmp -type f -size +10M -exec ls -lh {} \; 2>/dev/null | awk '{print $5, $NF}' | sort -hr | head -n 20;
echo;
echo "=== TOP 20 ARCHIVOS GRANDES EN Caches ===";
find ~/Library/Caches -type f -size +50M -exec ls -lh {} \; 2>/dev/null | awk '{print $5, $NF}' | sort -hr | head -n 20;
'''

# --- 9. USB / PERIFÉRICOS ---
CMD_MAC_USB = r'''
echo "=== DISPOSITIVOS USB ===";
system_profiler SPUSBDataType | sed 's/^ *//' | grep -E "Product ID|Vendor ID|Manufacturer|Location ID|Serial Number|^ *[A-Za-z0-9]" | head -n 60;
echo;
echo "=== DISCOS EXTERNOS / VOLÚMENES ===";
diskutil list external;
'''

# --- 10. RENDIMIENTO DE ARRANQUE (macOS: log del último boot) ---
CMD_MAC_STARTUP_PERF = r'''
echo "=== ÚLTIMO ARRANQUE (tiempo de boot) ===";
sysctl -n kern.boottime;
echo;
echo "=== APPS DE INICIO DE SESIÓN (login items) ===";
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "(no se pudo leer, requiere accesibilidad)";
echo;
echo "=== SERVICIOS DE INICIO (LaunchAgents/LaunchDaemons cargados) ===";
launchctl list | head -n 30;
echo;
echo "=== LOGS DE ARRANQUE (últimos eventos de boot) ===";
log show --last 2m --predicate 'eventMessage CONTAINS "boot" OR (subsystem CONTAINS "kernel")' 2>/dev/null | grep -iE "mach|boot|apfs" | head -n 10 || echo "(log show requiere permisos)";
'''

# --- 11. DRIVERS / KEXT / EXTENSIONES DEL SISTEMA ---
CMD_MAC_DRIVER_VERSIONS = r'''
echo "=== EXTENSIONES DEL SISTEMA (kext/DriverKit aprobadas) ===";
systemextensionsctl list 2>/dev/null || echo "(systemextensionsctl requiere permisos)";
echo;
echo "=== KEXTs CARGADAS ===";
kextstat 2>/dev/null | head -n 30 || echo "(kextstat requiere root en macOS 11+)";
echo;
echo "=== VERSIONES DE FIRMWARE/CHIP ===";
system_profiler SPHardwareDataType | sed 's/^ *//' | grep -iE "firmware|boot rom|smc|chip|model";
'''

# --- 12. ERRORES DE DRIVER / HARDWARE (logs unificado) ---
CMD_MAC_DRIVER_ERRORS = r'''
echo "=== ERRORES DEL SISTEMA (última 1h, nivel error/fault) ===";
log show --last 1h --style compact 2>/dev/null | grep -iE "error|fault|panic|kernel" | grep -viE "proactive|CKAccount|com.apple.telemetry" | tail -n 40 || echo "(sin logs accesibles)";
echo;
echo "=== PANICS / REINICIOS ANORMALES ===";
grep -iE "panic|restart due to|shutdown cause" /Library/Logs/DiagnosticReports/System*.ips 2>/dev/null | tail -n 10 || echo "(sin panics registrados o sin permisos)";
'''

# --- 13. DIAGNÓSTICO DE RED ---
CMD_MAC_NETWORK_DIAG = r'''
echo "=== INTERFACES ===";
networksetup -listallhardwareports;
echo;
echo "=== IPs ===";
ifconfig | grep "inet " | grep -v 127.0.0.1;
echo;
echo "=== DNS ===";
scutil --dns | grep nameserver | head;
echo;
echo "=== GATEWAY ===";
route -n get default 2>/dev/null | grep gateway;
echo;
echo "=== PING GATEWAY ===";
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}');
[ -n "$GW" ] && ping -c 2 -t 3 "$GW" || echo "sin gateway";
echo;
echo "=== PING 8.8.8.8 ===";
ping -c 2 -t 3 8.8.8.8 2>/dev/null || echo "sin internet";
echo;
echo "=== WIFI ===";
system_profiler SPAirPortDataType 2>/dev/null | sed 's/^ *//' | grep -iE "current network|signal|channel|security" | head;
'''

# --- 14. PANTALLA AZUL ---> en macOS: crash reports / panics ---
CMD_MAC_BLUE_SCREEN = r'''
echo "=== ERRORES DE KERNEL / PANICS (equivalente BSOD) ===";
ls -lt /Library/Logs/DiagnosticReports/ 2>/dev/null | head -n 20;
echo;
echo "=== ÚLTIMOS REPORTES DE CRASH ===";
find /Library/Logs/DiagnosticReports ~/Library/Logs/DiagnosticReports -type f \( -name "*.ips" -o -name "*.panic" \) -print 2>/dev/null | head -n 15;
echo;
echo "=== CAUSAS DE APAGADO (Shutdown cause) ===";
log show --last 7d --predicate 'eventMessage CONTAINS "Previous shutdown cause"' 2>/dev/null | tail -n 15 || echo "(requiere permisos)";
echo;
echo "=== FATAL ERRORS RECIENTES ===";
log show --last 1d --style compact --predicate 'messageType == 16 OR eventMessage CONTAINS "panic"' 2>/dev/null | tail -n 25 || echo "(requiere permisos)";
'''

# --- 15. ACTUALIZACIONES PENDIENTES ---
CMD_MAC_UPDATES = r'''
echo "=== SOFTWARE UPDATE PENDIENTE ===";
softwareupdate --list 2>/dev/null || echo "(softwareupdate requiere permisos)";
echo;
echo "=== QUICK LOOK: build actual ===";
sw_vers -buildVersion;
echo;
echo "=== XCODE CLI tools actualización ===";
xcode-select -p 2>/dev/null && softwareupdate --list 2>/dev/null | grep -i "Command Line" || echo "(CLT al día)";
'''

# --- 16. AUTOINICIO SOSPECHOSO (persistencia) ---
CMD_MAC_AUTOSTART = r'''
echo "=== LOGIN ITEMS ===";
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "(requiere accesibilidad)";
echo;
echo "=== LAUNCH AGENTS (usuario) ===";
ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo "(sin LaunchAgents de usuario)";
echo;
echo "=== LAUNCH DAEMONS (sistema) ===";
ls -la /Library/LaunchDaemons/ 2>/dev/null | head -n 40;
echo;
echo "=== AGENTS DEL SISTEMA ===";
ls -la /Library/LaunchAgents/ 2>/dev/null | head -n 40;
echo;
echo "=== PLIST CARGADOS (launchctl) ===";
launchctl list | head -n 40;
'''

# ---------------------------------------------------------------------------
# v2.0: MALWARE / RADAR / PERSISTENCIA (pila macOS)
# ---------------------------------------------------------------------------
CMD_MAC_MALWARE_SCAN = r'''
echo "==============================================";
echo "  🦠 MALWARE SCAN — PCTaller Diagnostics (macOS)";
echo "==============================================";

echo;
echo "[1/8] PROCESOS CON NOMBRES SOSPECHOSOS";
SUS=("crypto" "miner" "xmrig" "ethminer" "monero" "coinhive" "payload" "backdoor" "ransom" "keylog" "trojan" "beacon" "cobalt" "mimikatz" "psexec" "bloodhound");
ps -axo pid,%cpu,rss,comm | while read -r pid cpu rss comm; do
  n=$(basename "$comm" | tr 'A-Z' 'a-z');
  for s in "${SUS[@]}"; do
    case "$n" in
      *"$s"*) echo "  ⚠️ $n (PID $pid, CPU $cpu%, RAM $((rss/1024)) MB) — coincidencia: $s"; break;;
    esac;
  done;
done;
echo "  ✅ Revisión de nombres sospechosos completada";

echo;
echo "[2/8] PROCESOS DE UBICACIONES TEMPORALES/BAJADAS";
ps -axo pid,comm | grep -E "/(tmp|Downloads|Library/Caches|Library/Application Support)" | grep -v grep;

echo;
echo "[3/8] PROCESOS SIN FIRMA VÁLIDA (ejecutables sin spctl)";
for p in $(ps -axo comm | grep -E "\.app/Contents/MacOS/" | head -n 30); do
  app=$(echo "$p" | sed 's#/Contents/MacOS/.*##');
  sig=$(codesign -dv "$app" 2>&1 | grep -iE "authority=|flags=" | head -n 1);
  echo "  $p";
  echo "    → ${sig:-SIN FIRMA/DESCONOCIDO}";
done;

echo;
echo "[4/8] PROCESOS CON PADRE SHELL SOSPECHOSO";
ps -axo pid,ppid,comm | while read -r pid ppid comm; do
  pp=$(ps -p "$ppid" -o comm= 2>/dev/null);
  case "$pp" in
    *sh*|*python*|*osascript*) echo "  PID $pid ($comm) → padre: $pp";;
  esac;
done;

echo;
echo "[5/8] CONEXIONES DE RED ESTABLECIDAS (no sistema)";
lsof -nP -iTCP -sTCP:ESTABLISHED | head -n 30;

echo;
echo "[6/8] PUERTOS EN ESCUCHA >1024 (procesos no Apple)";
lsof -nP -iTCP -sTCP:LISTEN | awk '$9 ~ /:[0-9]+$/ {split($9,a,":"); if(a[length(a)]>1024) print $1, $2, $9}' | head -n 25;

echo;
echo "[7/8] LAUNCHAGENTS CARPETAS USUARIO NO ESTÁNDAR";
ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -vE "com\.apple|^total|^d.* \.\.?$" | head;

echo;
echo "[8/8] PROCESOS ENMASCARADOS / NOMBRES ANÓMALOS";
ps -axo comm | grep -vE "^/usr|^/System|^/Applications|^/sbin|^/bin|^/opt" | grep -v grep | grep -E "\.(dylib|sh|py)$" | head;

echo;
echo "==============================================";
echo "  🦠 MALWARE SCAN COMPLETADO";
echo "==============================================";
'''

CMD_MAC_RADAR = r'''
echo "==============================================";
echo "  📡 RADAR DE PROCESOS — PCTaller Diagnostics (macOS)";
echo "==============================================";

echo;
echo "[1/7] TOP 10 CPU";
ps -arcwwwxo %cpu,pid,rss,comm | head -n 11;

echo;
echo "[2/7] TOP 10 RAM";
ps -axmww -o rss,pid,%cpu,comm | sort -rn | head -n 11;

echo;
echo "[3/7] PROCESOS MULTI-INSTANCIA";
ps -axo comm | sort | uniq -c | sort -rn | awk '$1>1 && $2 !~ /^$/ {print $1, $2}' | head -n 15;

echo;
echo "[4/7] PROCESOS DESDE TEMP / CACHES / DOWNLOADS";
ps -axo pid,comm | grep -E "/(tmp|Downloads|Caches|Application Support/([^/]+)/)" | grep -v grep;

echo;
echo "[5/7] PROCESOS CON CONEXIONES DE RED ACTIVAS";
lsof -nP -iTCP -sTCP:ESTABLISHED | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn | head -n 15;

echo;
echo "[6/7] NOMBRES CON CARACTERES ENMASCARADOS";
ps -axo comm | grep -P "[^\x20-\x7E]" | grep -v grep | head || echo "  ✅ Sin caracteres enmascarados";

echo;
echo "[7/7] EJECUTABLES EN UBICACIONES INUSUALES";
ps -axo pid,comm | grep -E "\.(sh|py|pl|rb|js|command)$" | grep -v grep | head;

echo;
echo "==============================================";
echo "  📡 RADAR COMPLETADO";
echo "==============================================";
'''

CMD_MAC_PERSISTENCE = r'''
echo "==============================================";
echo "  🕵️ PERSISTENCIA — PCTaller Diagnostics (macOS)";
echo "==============================================";

echo;
echo "[1/8] LOGIN ITEMS (AppKit)";
osascript -e 'tell application "System Events" to get {name, path} of every login item' 2>/dev/null || echo "(requiere accesibilidad)";

echo;
echo "[2/8] LAUNCHAGENTS — Usuario";
ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -vE "^total|\.\.?$" | head -n 30;

echo;
echo "[3/8] LAUNCHAGENTS — Sistema (/Library)";
ls -la /Library/LaunchAgents/ 2>/dev/null | grep -vE "^total|\.\.?$" | head -n 40;

echo;
echo "[4/8] LAUNCHDAEMONS — Sistema (/Library)";
ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -vE "^total|\.\.?$" | head -n 40;

echo;
echo "[5/8] LAUNCHDAEMONS/AGENTS — Apple (solo conteo)";
echo "  Apple Daemons: $(ls /System/Library/LaunchDaemons/ 2>/dev/null | wc -l | tr -d ' ')";

echo;
echo "[6/8] LAUNCHCTL CARGADOS (no com.apple)";
launchctl list | awk '!/com\.apple/ && $3!="label" && $3!="" {print $1, $2, $3}' | head -n 40;

echo;
echo "[7/8] CRONTABS (usuario + root)";
crontab -l 2>/dev/null | grep -vE "^#" | grep -v "^$" || echo "  (sin crontab de usuario)";
sudo -n crontab -l 2>/dev/null | grep -vE "^#" | grep -v "^$" || true;

echo;
echo "[8/8] PLIST DE INICIO CON PROGRAMAS EXTERNOS";
grep -rlE "<key>RunAtLoad</key>" ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null | head -n 20;

echo;
echo "==============================================";
echo "  🕵️ PERSISTENCIA SCAN COMPLETADO";
echo "==============================================";
'''

CMD_MAC_NETWORK_OFFENSIVE = r'''
echo "==============================================";
echo "  🔒 SEGURIDAD OFENSIVA — PCTaller Diagnostics (macOS)";
echo "==============================================";

echo;
echo "[1/5] PUERTOS CRÍTICOS EN ESCUCHA";
lsof -nP -iTCP -sTCP:LISTEN | awk 'NR>1 {split($9,a,":"); p=a[length(a)]; if(p==22||p==21||p==23||p==3389||p==5900||p==445||p==3306||p==5432||p==6379) print $1, $2, $9}';

echo;
echo "[2/5] PUERTOS ALTOS EN ESCUCHA (>10000)";
lsof -nP -iTCP -sTCP:LISTEN | awk 'NR>1 {split($9,a,":"); p=a[length(a)]; if(p>10000) print $1, $2, $9}';

echo;
echo "[3/5] CONEXIONES ESTABLECIDAS A INTERNET (IP públicas)";
lsof -nP -iTCP -sTCP:ESTABLISHED | awk 'NR>1 {split($9,a,"->"); if(a[2] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:/){ip=a[2]; sub(/:.*/,"",ip); if(ip !~ /^(10\.|192\.168|172\.(1[6-9]|2[0-9]|3[01])|127\.)/) print ip, $1}}' | sort | uniq -c | sort -rn | head -n 20;

echo;
echo "[4/5] TOP PROCESOS POR CONEXIONES SALIENTES";
lsof -nP -iTCP -sTCP:ESTABLISHED | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn | head -n 10;

echo;
echo "[5/5] IPs REMOTAS ÚNICAS";
lsof -nP -iTCP -sTCP:ESTABLISHED | awk 'NR>1 {split($9,a,"->"); if(a[2] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:/){ip=a[2]; sub(/:.*/,"",ip); print ip}}' | sort -u | head -n 30;

echo;
echo "==============================================";
echo "  SEGURIDAD OFENSIVA COMPLETADO";
echo "==============================================";
'''

CMD_MAC_EVENT_CRITICAL = r'''
echo "=== ERRORES CRÍTICOS / FAULT (última 1h) ===";
log show --last 1h --style compact --predicate '(messageType == 16) OR (eventMessage CONTAINS[c] "panic") OR (eventMessage CONTAINS[c] "kernel trap")' 2>/dev/null | tail -n 40 || echo "(requiere permisos)";
echo;
echo "=== ÚLTIMOS CRASH REPORTS ===";
find /Library/Logs/DiagnosticReports ~/Library/Logs/DiagnosticReports -type f -name "*.ips" -print 2>/dev/null | head -n 15;
'''

CMD_MAC_EVENT_APP = r'''
echo "=== ERRORES DE APLICACIÓN (última 2h) ===";
log show --last 2h --style compact --predicate '(process == "ReportCrash") OR (eventMessage CONTAINS[c] "crash") OR (eventMessage CONTAINS[c] "abort")' 2>/dev/null | tail -n 40 || echo "(requiere permisos)";
echo;
echo "=== PROCESOS EN ESTADO ZOMBIE/DETENIDO ===";
ps -axo pid,state,comm | awk '$2 ~ /Z|T/';
'''

CMD_MAC_EVENT_ALL = r'''
echo "=== EVENTOS RECIENTES SISTEMA (fault+error, última 3h) ===";
log show --last 3h --style compact --predicate 'messageType == 16 OR messageType == 17' 2>/dev/null | tail -n 60 || echo "(requiere permisos)";
echo;
echo "=== KERNEL LOG (errores) ===";
log show --last 6h --predicate 'subsystem == "com.apple.kernel"' 2>/dev/null | grep -iE "error|fault|panic" | tail -n 25 || echo "(requiere permisos)";
'''

CMD_MAC_DISK_DETAIL = r'''
echo "=== DISCOS FÍSICOS ===";
diskutil list;
echo;
echo "=== VOLUMENES / PARTICIONES ===";
diskutil list internal | grep -E "/dev/disk|Apple_|EFI|GUID" | head -n 40;
echo;
echo "=== TIPOS + SALUD (SMART via smartctl si existe) ===";
which smartctl >/dev/null 2>&1 && diskutil list | awk '/^\/dev\//{print $1}' | while read d; do echo "--- $d ---"; smartctl -a "$d" 2>/dev/null | grep -iE "SMART Health|Model|Capacity|Rotation" || echo "(smartctl sin permisos/sin soporte)"; done || echo "smartctl no instalado (brew install smartmontools)";
echo;
echo "=== ESPACIO POR VOLUMEN ===";
df -h | grep -E "/dev/|/System/Volumes";
'''

CMD_MAC_DISK_BENCHMARK = r'''
echo "=== BENCHMARK DE DISCO (lectura rápida) ===";
echo "⚠️ macOS no trae winsat. Usamos dd + time (lectura de 1GB).";
TMPF=$(mktemp /tmp/pct_bench.XXXXXX);
echo "Generando 1GB...";
dd if=/dev/zero of="$TMPF" bs=1m count=1024 2>/dev/null;
echo;
echo "Lectura 1GB (buffered):";
sync; time dd if="$TMPF" of=/dev/null bs=1m count=1024 2>&1 | grep -E "copied|real";
echo;
echo "Escritura 1GB:";
time dd if=/dev/zero of="$TMPF" bs=1m count=1024 2>&1 | grep -E "copied|real";
rm -f "$TMPF";
echo;
echo "=== DRIVE INFO ===";
diskutil info / | grep -E "Device / Media Name|Protocol|SMART|Disk Size" | sed 's/^ *//';
'''

CMD_MAC_NETWORK_SCAN = r'''
echo "=== MAPA DE RED LOCAL ===";
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}');
echo "Gateway: $GW";
NID=$(echo "$GW" | awk -F. '{print $1"."$2"."$3".0/24"}');
echo "Subred: $NID";
echo;
echo "=== Hosts activos (ping sweep, rápido) ===";
BASE=$(echo "$GW" | awk -F. '{print $1"."$2"."$3}');
for i in $(seq 1 254); do
  (ping -c 1 -t 1 "$BASE.$i" >/dev/null 2>&1 && echo "  $BASE.$i activo") &
done;
wait;
echo;
echo "=== ARP / caché de vecinos ===";
arp -a | head -n 40;
'''

CMD_MAC_SPEEDTEST = r'''
echo "=== TEST DE VELOCIDAD (speedtest) ===";
if command -v speedtest-cli >/dev/null 2>&1; then
  speedtest-cli --simple 2>/dev/null || speedtest-cli 2>/dev/null;
elif command -v speedtest >/dev/null 2>&1; then
  speedtest --accept-license --accept-gdpr 2>/dev/null | head;
else
  echo "No hay speedtest-cli instalado. Instala con: brew install speedtest-cli";
  echo;
  echo "=== Fallback: latencia a servidores conocidos ===";
  echo "Ping Google DNS:"; ping -c 3 -t 3 8.8.8.8 2>/dev/null | tail -n 2;
  echo "Ping Cloudflare:"; ping -c 3 -t 3 1.1.1.1 2>/dev/null | tail -n 2;
  echo "Ping OpenDNS:"; ping -c 3 -t 3 208.67.222.222 2>/dev/null | tail -n 2;
fi
'''

CMD_MAC_SFC_DISM = r'''
echo "=== VERIFICACIÓN DE INTEGRIDAD del sistema (equivalente SFC/DISM en macOS) ===";
echo "macOS no usa SFC/DISM. Análogos:";
echo;
echo "1) Comprobación de disco de arranque:";
diskutil verifyVolume / 2>/dev/null || echo "   (synckill/verificación requiere arranque en Recuperación para scrub)";
echo;
echo "2) First Aid en volumen de datos:";
diskutil verifyVolume /System/Volumes/Data 2>/dev/null || true;
echo;
echo "3) Permisos de archivos (prueba rápida en /System):";
ls -ld /System >/dev/null 2>&1 && echo "   /System accesible (leer)";
echo;
echo "4) Ultimo fsck / arranque limpio (kernel):";
log show --last 24h --predicate 'eventMessage CONTAINS "fsck" OR eventMessage CONTAINS "apfs"' 2>/dev/null | grep -iE "fsck|error|rebuild" | tail -n 10 || true;
'''

# ---------------------------------------------------------------------------
# MAPA DE COMANDOS
# ---------------------------------------------------------------------------
# command_type -> (script macOS, descripción)
MAC_COMMANDS = {
    "system_health": CMD_MAC_SYSTEM_HEALTH,
    "hardware_info": CMD_MAC_HARDWARE,
    "temperatures": CMD_MAC_TEMPERATURES,
    "battery": CMD_MAC_BATTERY,
    "licenses": CMD_MAC_LICENSES,
    "ports": CMD_MAC_PORTS,
    "installed_software": CMD_MAC_INSTALLED_SOFTWARE,
    "temp_files": CMD_MAC_TEMP_FILES,
    "usb_history": CMD_MAC_USB,
    "startup_perf": CMD_MAC_STARTUP_PERF,
    "driver_versions": CMD_MAC_DRIVER_VERSIONS,
    "driver_errors": CMD_MAC_DRIVER_ERRORS,
    "blue_screen_analysis": CMD_MAC_BLUE_SCREEN,
    "updates_pending": CMD_MAC_UPDATES,
    "autostart_suspicious": CMD_MAC_AUTOSTART,
    "disk_detail": CMD_MAC_DISK_DETAIL,
    "disk_benchmark": CMD_MAC_DISK_BENCHMARK,
    "network_diagnostics": CMD_MAC_NETWORK_DIAG,
    "network_scan": CMD_MAC_NETWORK_SCAN,
    "speedtest": CMD_MAC_SPEEDTEST,
    "sfc_dism": CMD_MAC_SFC_DISM,
    "event_logs": CMD_MAC_EVENT_ALL,
    "event_log_critical": CMD_MAC_EVENT_CRITICAL,
    "event_log_app": CMD_MAC_EVENT_APP,
    "event_log_all": CMD_MAC_EVENT_ALL,
    # v2.0
    "malware_scan": CMD_MAC_MALWARE_SCAN,
    "radar_procesos": CMD_MAC_RADAR,
    "persistence_scan": CMD_MAC_PERSISTENCE,
    "network_offensive": CMD_MAC_NETWORK_OFFENSIVE,
}


# Detecta el diagnóstico a partir del cuerpo de un script PowerShell (útil
# cuando el server envía run_diagnostics con command_type="custom_powershell").
def detect_diag_from_ps_body(body):
    b = body or ""
    markers = {
        "MALWARE SCAN": "malware_scan",
        "MALWARE FULL SCAN": "malware_full",
        "RADAR DE PROCESOS": "radar_procesos",
        "PERSISTENCIA — PCTaller": "persistence_scan",
        "SEGURIDAD OFENSIVA": "network_offensive",
        "SALUD DEL SISTEMA": "system_health",
        "DISCOS": "system_health",
        "PANTALLAZOS AZULES": "blue_screen_analysis",
        "CONFIGURACION DE RED": "network_diagnostics",
        "DISPOSITIVOS CON ERRORES": "driver_errors",
        "RENDIMIENTO DE ARRANQUE": "boot_performance",
        "ACTUALIZACIONES PENDIENTES": "updates_pending",
        "AUTOINICIOS (STARTUP)": "autostart_suspicious",
        "EVENTOS CRITICOS": "event_log_critical",
        "EVENTOS / LOGS": "event_log_all",
        "BENCHMARK": "disk_benchmark",
        "TEMPERATURAS": "temperatures",
        "BATERIA": "battery",
        "LICENCIAS": "licenses",
        "PUERTOS ABIERTOS": "ports",
        "PROGRAMAS INSTALADOS": "installed_software",
        "ARCHIVOS TEMPORALES": "temp_files",
        "DISPOSITIVOS USB": "usb_history",
        "VERSIONES DE DRIVERS": "driver_versions",
        "DISCOS FISICOS": "disk_detail",
        "SIMPLICIDAD SFC": "sfc_dism",
        "SFCDISM": "sfc_dism",
        "MAPA DE RED": "network_scan",
        "TEST DE VELOCIDAD": "speedtest",
    }
    for marker, diag in markers.items():
        if marker in b.upper():
            return diag
    return None


# ---------------------------------------------------------------------------
# INFORMACIÓN DEL SISTEMA (get_info)
# ---------------------------------------------------------------------------
def get_system_info():
    info = {
        "hostname": AGENT_NAME,
        "user": AGENT_USER,
        "os": "macOS",
        "version": VERSION,
    }
    try:
        sw = subprocess.run(["sw_vers"], capture_output=True, text=True).stdout
        for line in sw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info["sw_" + k.strip().lower().replace(" ", "_")] = v.strip()
    except Exception:
        pass
    if psutil:
        try:
            info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            info["cpu_percent"] = psutil.cpu_percent(interval=1)
            info["ram_total_gb"] = round(psutil.virtual_memory().total / (1024 ** 3), 2)
            info["ram_percent"] = psutil.virtual_memory().percent
        except Exception:
            pass
    return json.dumps(info, indent=2)


# ---------------------------------------------------------------------------
# COMANDOS ESPECIALES
# ---------------------------------------------------------------------------
async def handle_special_command(cmd_type, params):
    gui_log("info", f"📦 Ejecutando diagnóstico: {cmd_type}")

    if cmd_type == "get_info":
        gui_log("result", "✅ Información del sistema obtenida")
        return get_system_info()

    if cmd_type == "custom_shell" or cmd_type == "bash":
        cmd = params.get("command", "")
        gui_log("cmd", f"📜 Shell personalizado: {cmd[:100]}")
        return await execute_custom_shell(cmd)

    if cmd_type == "custom_powershell":
        script = params.get("command", "") or ""
        diag = detect_diag_from_ps_body(script)
        if diag and diag in MAC_COMMANDS:
            gui_log("info", f"🔁 Script PowerShell Windows detectado → ejecutando equivalente macOS: {diag}")
            return await run_sh(MAC_COMMANDS[diag])
        gui_log("warn", "🧩 Script PowerShell Windows no interpretable en macOS (sin equivalente automático).")
        return ("[macOS] Este comando llegó como script PowerShell de Windows y no se puede ejecutar "
                "en macOS. Usa: system_health, malware_scan, radar_procesos, persistence_scan, "
                "network_offensive, ports, disk_detail, etc. Si tienes un comando shell nativo, "
                "úsalo vía custom_shell.")

    if cmd_type in MAC_COMMANDS:
        gui_log("info", f"→ Ejecutando {cmd_type} (versión macOS)")
        return await run_sh(MAC_COMMANDS[cmd_type])

    if cmd_type == "full_threat_scan":
        gui_log("malware", "🔥 ESCANEO COMPLETO DE AMENAZAS — macOS")
        results = []
        for cname in ["malware_scan", "radar_procesos", "persistence_scan"]:
            gui_log("info", f"  └── Fase: {cname}")
            r = await run_sh(MAC_COMMANDS[cname])
            results.append(f"\n{'='*60}\n=== {cname.upper()} ===\n{'='*60}\n{r}")
        gui_log("ok", "✅ Escaneo completo finalizado")
        return "\n".join(results)

    if cmd_type == "custom_cmd":
        # En macOS mapeamos cmd -> sh
        cmd = params.get("command", "")
        gui_log("cmd", f"📜 CMD→sh: {cmd[:80]}")
        return await execute_custom_shell(cmd)

    if cmd_type == "powershell":
        # El server puede enviar command_type="powershell" con script suelto
        script = params.get("command", "") or ""
        diag = detect_diag_from_ps_body(script)
        if diag and diag in MAC_COMMANDS:
            return await run_sh(MAC_COMMANDS[diag])
        gui_log("warn", "🧩 Script PowerShell no mapeable en macOS.")
        return "[macOS] Script PowerShell no ejecutable. Usa command_type nativo (system_health, ports, bash, custom_shell)."

    else:
        gui_log("warn", f"❓ Comando desconocido: {cmd_type}")
        return f"ERROR: Comando desconocido '{cmd_type}'"


# ---------------------------------------------------------------------------
# CONEXIÓN WEBSOCKET
# ---------------------------------------------------------------------------
async def connect_and_serve():
    uris = [f"ws://{h}:{SERVER_PORT}" for h in SERVER_HOSTS]
    gui_log("info", "🌐 PCTaller Diagnostics Agent v2.0 (macOS)")
    gui_log("info", f"🌐 Servidores: {', '.join(uris)}")
    gui_log("info", f"🖥️  {AGENT_NAME} | 👤 {AGENT_USER}")
    gui_log("info", "🆕 Nuevo: malware_scan | radar_procesos | persistence_scan | full_threat_scan")

    while True:
        connected = False
        for uri in uris:
            try:
                gui_log("info", f"🔌 Intentando conectar a {uri}...")
                window.update_status(f"🔌 Conectando a {uri}...")

                async with websockets.connect(
                    uri, ping_interval=30, ping_timeout=10, max_size=2 ** 24
                ) as websocket:
                    gui_log("ok", f"✅ Conectado a {uri}")
                    window.update_status(f"✅ Conectado a {uri}")

                    handshake = {
                        "type": "handshake",
                        "name": f"{AGENT_NAME}@{AGENT_USER}",
                        "os": f"macOS {socket.gethostname()}",
                        "version": VERSION,
                    }
                    await websocket.send(json.dumps(handshake))
                    try:
                        resp = await asyncio.wait_for(websocket.recv(), timeout=15)
                        gui_log("ok", f"📡 Servidor: {str(resp)[:100]}")
                    except asyncio.TimeoutError:
                        pass

                    async for raw_msg in websocket:
                        try:
                            msg = json.loads(raw_msg)
                            msg_type = msg.get("type", "")

                            if msg_type == "execute":
                                cmd_id = msg.get("id", str(uuid.uuid4()))
                                command = msg.get("command", "")
                                command_type = msg.get("command_type", "custom_powershell")
                                params = msg.get("params", {})

                                gui_log("cmd", f"📨 [{cmd_id[:8]}]: {command_type}")
                                window.update_status(f"⚡ Ejecutando: {command_type}")

                                if command_type == "powershell":
                                    output = await handle_special_command("powershell", {"command": command})
                                elif command_type == "custom_powershell":
                                    output = await handle_special_command("custom_powershell", {"command": command})
                                else:
                                    if not command:
                                        params["command"] = command
                                    output = await handle_special_command(command_type, params)

                                result = {
                                    "type": "command_result",
                                    "id": cmd_id,
                                    "status": "ok" if not output.startswith("ERROR") else "error",
                                    "output": output[:MAX_OUTPUT],
                                }
                                await websocket.send(json.dumps(result))
                                gui_log("result", f"📤 [{cmd_id[:8]}]: {result['status']} ({len(output)} chars)")
                                window.update_status(f"✅ [{cmd_id[:8]}] {result['status']}")

                            elif msg_type == "ping":
                                await websocket.send(json.dumps({"type": "pong"}))

                            elif msg_type == "disconnect":
                                gui_log("warn", "🔌 Servidor solicitó desconexión")
                                break

                        except json.JSONDecodeError:
                            gui_log("error", f"📄 Mensaje inválido: {raw_msg[:100]}")
                        except Exception as e:
                            gui_log("error", f"⚠️ Error procesando mensaje: {e}")
                            try:
                                await websocket.send(json.dumps({
                                    "type": "command_result",
                                    "id": msg.get("id", "unknown"),
                                    "status": "error",
                                    "output": f"ERROR: {str(e)[:500]}",
                                }))
                            except Exception:
                                pass

                    connected = True
                    break

            except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
                gui_log("warn", f"⚠️ {uri}: {type(e).__name__}")
                continue
            except Exception as e:
                gui_log("error", f"⚠️ Error inesperado en {uri}: {e}")
                continue

        if not connected:
            gui_log("warn", f"🔌 Ningún servidor disponible. Reintentando en {RECONNECT_DELAY}s...")
            window.update_status("🔌 Sin servidor — reintentando...")
        else:
            gui_log("warn", f"🔌 Conexión perdida. Reintentando en {RECONNECT_DELAY}s...")
            window.update_status("🔌 Reconectando...")
        await asyncio.sleep(RECONNECT_DELAY)


# ---------------------------------------------------------------------------
# SELFTEST (headless) — prueba diagnósticos + WebSocket sin servidor externo
# ---------------------------------------------------------------------------
SELFTEST_DIAGS = [
    ("system_health", "df, sysctl, vm_stat, uptime, ps"),
    ("hardware_info", "system_profiler"),
    ("ports", "lsof, netstat"),
    ("installed_software", "/Applications + brew"),
    ("disk_detail", "diskutil"),
    ("network_diagnostics", "networksetup, route, ping"),
    ("malware_scan", "ps, codesign, lsof"),
    ("radar_procesos", "ps, lsof"),
    ("persistence_scan", "launchctl, osascript"),
]


async def _selftest_ws_roundtrip():
    """Prueba handshake + ping + execute(get_info) contra un servidor local."""
    import websockets
    host, port = "127.0.0.1", 18791
    received = {}

    async def mock_handler(ws):
        hs = json.loads(await ws.recv())
        received["handshake"] = hs
        await ws.send(json.dumps({"type": "ok", "msg": "welcome"}))
        await ws.send(json.dumps({"type": "ping"}))
        received["pong"] = json.loads(await ws.recv())
        await ws.send(json.dumps({"type": "execute", "id": "st1", "command": "",
                                 "command_type": "get_info", "params": {}}))
        received["result"] = json.loads(await ws.recv())
        await ws.close()

    server = await websockets.serve(mock_handler, host, port)
    try:
        async with websockets.connect(f"ws://{host}:{port}") as ws:
            await ws.send(json.dumps({"type": "handshake",
                                      "name": f"{AGENT_NAME}@{AGENT_USER}",
                                      "os": "macOS", "version": VERSION}))
            await ws.recv()  # welcome
            ping = json.loads(await ws.recv())
            if ping.get("type") == "ping":
                await ws.send(json.dumps({"type": "pong"}))
            ex = json.loads(await ws.recv())
            if ex.get("type") == "execute":
                out = await handle_special_command(ex.get("command_type", "get_info"), ex.get("params", {}))
                await ws.send(json.dumps({"type": "command_result", "id": ex.get("id"),
                                          "status": "ok" if not out.startswith("ERROR") else "error",
                                          "output": out[:500]}))
    finally:
        server.close()
        await server.wait_closed()

    hs_ok = received.get("handshake", {}).get("name") == f"{AGENT_NAME}@{AGENT_USER}"
    pong_ok = received.get("pong", {}).get("type") == "pong"
    res_ok = received.get("result", {}).get("status") == "ok"
    return hs_ok and pong_ok and res_ok


async def run_selftest():
    print("=" * 60)
    print("  PCTaller Diagnostics — SELFTEST (macOS)")
    print(f"  Host: {AGENT_NAME} | User: {AGENT_USER} | {VERSION}")
    print("=" * 60)

    results = []
    for name, desc in SELFTEST_DIAGS:
        script = MAC_COMMANDS.get(name, "")
        if not script:
            print(f"\n[SKIP] {name} (no script)")
            continue
        print(f"\n[RUN ] {name} ({desc})")
        out = await run_sh(script, timeout=90)
        ok = not out.startswith("ERROR")
        print(f"[{('PASS' if ok else 'FAIL')}] {name} — {len(out)} chars")
        if not ok:
            print("  " + out[:400])
        results.append((name, ok))

    print("\n" + "=" * 60)
    print("  TEST WEBSOCKET (handshake + ping + execute)")
    print("=" * 60)
    ws_ok = False
    try:
        ws_ok = await _selftest_ws_roundtrip()
        print(f"[{'PASS' if ws_ok else 'FAIL'}] websocket_roundtrip")
    except Exception as e:
        print(f"[FAIL] websocket_roundtrip: {e}")
    results.append(("websocket_roundtrip", ws_ok))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print("\n" + "=" * 60)
    print(f"  RESULTADO: {passed}/{total} PASS")
    for name, ok in results:
        print(f"    [{'PASS' if ok else 'FAIL'}] {name}")
    print("=" * 60)
    return 0 if passed == total else 1


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main():
    if SELFTEST:
        try:
            rc = asyncio.run(run_selftest())
        except Exception as e:
            print(f"SELFTEST FATAL: {e}")
            rc = 1
        sys.exit(rc)
    gui_log("info", "=" * 55)
    gui_log("info", "🚀 PCTaller Diagnostics Agent v2.0 (macOS)")
    gui_log("info", f"   Hostname: {AGENT_NAME}")
    gui_log("info", f"   Usuario: {AGENT_USER}")
    gui_log("info", f"   Servidores: {', '.join([f'{h}:{SERVER_PORT}' for h in SERVER_HOSTS])}")
    gui_log("info", "   🦠 malware_scan | 🕵️ persistence_scan | 📡 radar_procesos | 🔒 network_offensive")
    gui_log("info", "=" * 55)
    try:
        asyncio.run(connect_and_serve())
    except KeyboardInterrupt:
        gui_log("warn", "🛑 Agente detenido por el usuario")
    except Exception as e:
        gui_log("error", f"💥 Error fatal: {e}")
    finally:
        gui_log("info", "🏁 Agente finalizado")


if __name__ == "__main__":
    main()
