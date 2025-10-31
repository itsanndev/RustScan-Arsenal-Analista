
## 🎯 Índice
1. [Métodos de Instalación](#métodos-de-instalación)
2. [Instalación en Kali Linux](#instalación-en-kali-linux)
3. [Instalación en Ubuntu/Debian](#instalación-en-ubuntudebian)
4. [Instalación en macOS](#instalación-en-macos)
5. [Instalación en Windows](#instalación-en-windows)
6. [Instalación con Docker](#instalación-con-docker)
7. [Instalación desde Cargo](#instalación-desde-cargo)
8. [Compilación desde Fuentes](#compilación-desde-fuentes)
9. [Configuración Avanzada](#configuración-avanzada)
10. [Troubleshooting](#troubleshooting)

---

<a id="métodos-de-instalación"></a>
## 🎁 Métodos de Instalación

### Resumen de Opciones Disponibles

|Método|Dificultad|Ventajas|Recomendado para|
|---|---|---|---|
|**Paquetes DEB**|🟢 Fácil|Instalación rápida|Kali Linux, Ubuntu|
|**Docker**|🟢 Fácil|Aislamiento, limpio|Todos los sistemas|
|**Cargo**|🟡 Media|Siempre actualizado|Desarrolladores|
|**Binarios**|🟡 Media|Portable|Sistemas múltiples|
|**Compilación**|🔴 Difícil|Máximo control|Desarrolladores Rust|

---

<a id="instalación-en-kali-linux"></a>
## 🐍 Instalación en Kali Linux

```
# Actualizar repositorios
sudo apt update

# Instalar RustScan desde repositorio oficial
sudo apt install rustscan

# Verificar instalación
rustscan --version

```
### Método Alternativo: Descarga Directa DEB

```
# Descargar la última versión
wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb

# Instalar el paquete
sudo dpkg -i rustscan_2.1.1_amd64.deb

# Si hay dependencias faltantes
sudo apt install -f
```

### Verificación de Instalación

```
# Verificar versión y funcionalidad básica
rustscan --version
rustscan --help

# Prueba básica de escaneo (localhost)
rustscan -a 127.0.0.1 --scan-order sequential

```
---

<a id="instalación-en-ubuntudebian"></a>
## 🐧 Instalación en Ubuntu/Debian

### Para Ubuntu 20.04+ / Debian 11+
```
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias necesarias
sudo apt install libssl-dev nmap

# Descargar e instalar RustScan
wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
sudo dpkg -i rustscan_2.1.1_amd64.deb

# Configurar PATH si es necesario
export PATH=$PATH:/usr/local/bin

```
### Solución de Problemas Comunes

```
# Si falla la instalación por dependencias
sudo apt --fix-broken install

# Si nmap no está instalado
sudo apt install nmap

# Si hay problemas de librerías
sudo apt install libc6-dev
```

---

<a id="instalación-en-macos"></a>
## 🍎 Instalación en macOS

### Método 1: Homebrew (Recomendado)

```
# Instalar Homebrew si no está disponible
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar RustScan
brew install rustscan

# Verificar instalación
rustscan --version
```

### Método 2: Binarios Precompilados

# Descargar binario para macOS
```
curl -LO https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan-2.1.1-macos-x86_64.tar.gz

# Extraer
tar -xzf rustscan-2.1.1-macos-x86_64.tar.gz

# Mover a directorio ejecutable
sudo mv rustscan /usr/local/bin/

# Limpiar archivos temporales
rm rustscan-2.1.1-macos-x86_64.tar.gz

```
### Configuración en macOS
```
# Aumentar límite de archivos para mejor rendimiento
sudo launchctl limit maxfiles 65536 200000
ulimit -n 65536

# Verificar configuración
ulimit -n
```

---

<a id="instalación-en-windows"></a>
## 🪟 Instalación en Windows

### Método 1: Chocolatey

```
# Instalar Chocolatey si no está disponible
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Instalar RustScan
choco install rustscan

# Verificar instalación
rustscan --version
```
### Método 2: Binarios Manuales
# Descargar binario para Windows
```
curl -LO https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan-2.1.1-windows-x86_64.zip

# Extraer archivo ZIP
Expand-Archive rustscan-2.1.1-windows-x86_64.zip -DestinationPath C:\Tools\RustScan\

# Agregar al PATH
setx PATH "%PATH%;C:\Tools\RustScan\"

# Reiniciar terminal y verificar
rustscan --version
```

### Método 3: WSL2

```
# En WSL2 (Ubuntu)
sudo apt update && sudo apt install rustscan

# Verificar
rustscan -a 127.0.0.1
```

---

<a id="instalación-con-docker"></a>
## 🐳 Instalación con Docker

### Método Básico

```
# Pull de la imagen oficial
docker pull rustscan/rustscan:latest

# Ejecución básica
docker run -it --rm --name rustscan rustscan/rustscan:latest -a 192.168.1.1

# Con montaje de volumen para scripts personalizados
docker run -it --rm -v $(pwd)/scripts:/scripts rustscan/rustscan:latest -a 192.168.1.1 --scripts custom
```

### Método Avanzado con Docker Compose

```
# docker-compose.yml
version: '3.8'
services:
  rustscan:
    image: rustscan/rustscan:latest
    container_name: rustscan-scanner
    volumes:
      - ./scripts:/scripts
      - ./results:/results
    network_mode: "host"
    privileged: true
    command: ["-a", "192.168.1.0/24", "--", "-sC", "-sV"]
```


```
# Ejecutar con Docker Compose
docker-compose up

# Ejecutar en background
docker-compose up -d
```

<a id="instalación-desde-cargo"></a>
## 📦 Instalación desde Cargo

### Prerrequisitos
```
# Instalar Rust y Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Recargar entorno
source ~/.cargo/env

# Verificar instalación
cargo --version
rustc --version
```

### Instalación de RustScan
```
# Instalar desde crates.io
cargo install rustscan

# O instalar versión específica
cargo install rustscan --version 2.1.1

# Instalar con características específicas
cargo install rustscan --features "enable_scripts"

```
### Actualización via Cargo
```
# Actualizar RustScan
cargo install rustscan --force

# Actualizar Rust toolchain
rustup update
```

---

<a id="compilación-desde-fuentes"></a>
## 🔨 Compilación desde Fuentes

### Clonar y Compilar

```
# Clonar repositorio
git clone https://github.com/RustScan/RustScan.git
cd RustScan

# Compilar en modo release
cargo build --release

# El binario estará en:
./target/release/rustscan

# Instalar globalmente
sudo cp ./target/release/rustscan /usr/local/bin/

# Verificar
rustscan --version
```

### Dependencias de Compilación
```
# Ubuntu/Debian
sudo apt install build-essential libssl-dev pkg-config

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel

# macOS
xcode-select --install
brew install openssl
```

### Compilación con Características Específicas

```
# Compilar con todas las características
cargo build --release --all-features

# Compilar solo características esenciales
cargo build --release --no-default-features

# Compilar para producción optimizada
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

---

<a id="configuración-avanzada"></a>
## ⚙️ Configuración Avanzada

### Archivo de Configuración Global
```
# ~/.rustscan.toml
# Configuración global de RustScan

[scan]
batch_size = 10000
timeout = 2000
scan_order = "Serial"
tcp_port_timeout = 1000
greppable = false

[scripts]
default_script = "nmap"
script_timeout = 30

[performance]
ulimit = 65535
adaptive_learning = true
```

### Variables de Entorno
```
# Configurar en ~/.bashrc o ~/.zshrc
export RUSTSCAN_BATCH_SIZE=5000
export RUSTSCAN_TIMEOUT=1500
export RUSTSCAN_SCAN_ORDER="Random"
export RUSTSCAN_GREPPABLE=false

# Recargar configuración
source ~/.bashrc

```
### Configuración del Motor de Scripting (RSE)

```
# ~/.rustscan_scripts.toml
# Configuración de scripts personalizados

[scripts]
tags = ["http", "security", "scanning"]
ports = ["80", "443", "8080", "8443"]
developer = ["security-team"]
call_format = "python3 {{script}} {{ip}} {{port}}"

[[custom_scripts]]
name = "http-scanner"
path = "~/scripts/http-scanner.py"
tags = ["http", "web"]
trigger_ports = ["80", "443", "8080", "8443"]

```

### Optimización de Rendimiento por Sistema

#### Para Sistemas Linux de Alto Rendimiento
```
# Aumentar límites del sistema
echo 'fs.file-max = 1000000' | sudo tee -a /etc/sysctl.conf
echo '* soft nofile 1000000' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 1000000' | sudo tee -a /etc/security/limits.conf

# Aplicar cambios
sudo sysctl -p
ulimit -n 1000000
```

#### Para Sistemas con Recursos Limitados

```
# ~/.rustscan.toml para sistemas limitados
[scan]
batch_size = 1000
timeout = 5000
tcp_port_timeout = 3000

[performance]
ulimit = 1024
adaptive_learning = true
```

---

<a id="troubleshooting"></a>
## 🔧 Troubleshooting

### Problemas Comunes y Soluciones

```
#### Error: "Too many open files"

# Solución en Linux/macOS
ulimit -n 65535

# O temporalmente
sudo prlimit --pid=$$ --nofile=65535:65535

# Solución permanente en Linux
echo 'fs.file-max = 1000000' | sudo tee -a /etc/sysctl.conf
```

#### Error: "Connection reset by peer"
```
# Reducir batch size y aumentar timeout
rustscan -a 192.168.1.1 -b 1000 --timeout 3000

# Usar orden aleatorio
rustscan -a 192.168.1.1 --scan-order random
```

#### Error: "Nmap not found"
```
# Instalar nmap
sudo apt install nmap  # Debian/Ubuntu
sudo yum install nmap  # CentOS/RHEL
brew install nmap      # macOS

# Verificar instalación
nmap --version
```

#### Problemas de Permisos
```
# En sistemas Unix, algunos escaneos requieren privilegios
sudo rustscan -a 192.168.1.1 -- -sS

# O configurar capacidades (Linux)
sudo setcap cap_net_raw+ep $(which rustscan)
```

#### RustScan No Inicia

```
# Verificar dependencias
ldd $(which rustscan)

# Reinstalar desde binario
curl -s https://raw.githubusercontent.com/RustScan/RustScan/master/install.sh | sh

# Verificar versión de Rust
rustc --version
```

### Verificación de Instalación Completa

```
#!/bin/bash
# verification-script.sh

echo "VERIFICAR INSTALACIÓN"

# Verificar binario
if command -v rustscan &> /dev/null; then
    echo "RustScan encontrado en: $(which rustscan)"
    echo "Versión: $(rustscan --version)"
else
    echo "RustScan no encontrado en PATH"
    exit 1
fi

# Verificar nmap
if command -v nmap &> /dev/null; then
    echo "Nmap ENCONTRADO: $(nmap --version | head -n1)"
else
    echo "Nmap NO encontrado!! - la integración estará limitada"
fi

# Verificar límites del sistema
echo "Límite de archivos: $(ulimit -n)"

# Prueba funcional básica
echo " Ejecutando prueba de escaneo local:"
timeout 10s rustscan -a 127.0.0.1 -p 22,80,443 --greppable > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "Prueba de escaneo EXITOSA"
else
    echo "Prueba de escaneo FALLIDA"
fi

echo "VERIFICACIÓN COMPLETADA"
```

### Comandos de Diagnóstico
```
# Información del sistema para troubleshooting
rustscan --help
ulimit -a
cargo version  # Si se instaló desde fuente
docker --version  # Si se usa Docker
```

---
