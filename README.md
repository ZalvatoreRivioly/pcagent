# PCTaller Diagnostics — Cliente macOS 🍎

Cliente nativo macOS del agente de diagnóstico remoto PCTaller Diagnostics v2.0.

Se compila automáticamente en la nube (GitHub Actions, runner macOS) y produce
un **binario único** descargable desde la pestaña **Actions → run → Artifacts**.

## Compilación automática (GitHub Actions)

El workflow `.github/workflows/build-macos.yml` se dispara en cada push a `main`
o manualmente desde la pestaña **Actions → Build macOS → Run workflow**.

Resultado: `PCTaller-Diagnostics-macos-arm64` → binario `PCTaller-Diagnostics`.

## Compilar localmente (opcional)

```bash
brew install python-tk
python3 -m pip install pyinstaller websockets psutil
pyinstaller --onefile --windowed --name "PCTaller-Diagnostics" \
  --hidden-import websockets --hidden-import psutil \
  --hidden-import tkinter --hidden-import tkinter.scrolledtext \
  agent_client_macos.py
```

## Ejecutar

```bash
./PCTaller-Diagnostics
```

O renombrar a `.command` para abrir con doble clic desde Finder:
```bash
cp PCTaller-Diagnostics ~/Desktop/PCTaller-Diagnostics.command
chmod +x ~/Desktop/PCTaller-Diagnostics.command
```

## Conexión

Servidor por defecto: `192.168.254.235:18790` (LAN) y `100.105.219.40` (Tailscale).
Edita `SERVER_HOSTS` en `agent_client_macos.py` si cambian.

---
PCTaller Diagnostics v2.0 · BEERBOT · 2026-08-14
