# ⚙️ Development Environment Toolkit (WSL)
A simple toolkit to **check**, **start**, **stop**, or **install** your development stack.

Includes:
- Docker
- PostgreSQL
- Node.js + npm
- Prisma CLI

---

## 🧰 Requirements
- Windows Subsystem for Linux (WSL 2)
- Ubuntu or Debian terminal
- Internet connection (for installation)

---

## 📦 Files Included
| File | Description |
|------|--------------|
| `env-check.sh` | Checks if Docker, PostgreSQL, Node.js, and Prisma are installed and running |
| `env-control.sh` | Allows you to start, stop, or install Docker and PostgreSQL |
| `README.md` | This help guide |

---

## 🚀 How to Use

1. Open your WSL terminal (Ubuntu).
2. Navigate to your project directory:
   ```bash
   cd /mnt/c/Users/George\ M.\ Ngugi/Desktop/Backend\ Full\ Course/chapter_4
   ```

3. Make both scripts executable:
   ```bash
   chmod +x env-check.sh env-control.sh
   ```

---

### 🩺 Run the Environment Health Checker
Checks if everything is installed and running.
```bash
./env-check.sh
```

---

### ⚙️ Control Docker & PostgreSQL
Start, stop, or install components:

| Command | Description |
|----------|--------------|
| `./env-control.sh start` | Start Docker and PostgreSQL |
| `./env-control.sh stop` | Stop Docker and PostgreSQL |
| `./env-control.sh install` | Install Docker, PostgreSQL, Node.js, and Prisma |

---

## ✅ Example Output
```bash
🐳 Docker version 27.1.1
✅ Docker is running
🐘 PostgreSQL 15.4
✅ PostgreSQL is running
🟢 Node v22.9.0 | npm 10.9.0
✅ Node.js and npm installed
🧩 Prisma 5.4.2
✅ Prisma is installed
```
