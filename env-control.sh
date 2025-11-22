#!/bin/bash
ACTION=$1

start_env() {
    echo "🚀 Starting Docker and PostgreSQL..."
    sudo service docker start 2>/dev/null && echo "✅ Docker started" || echo "⚠️ Docker may already be running"
    sudo service postgresql start 2>/dev/null && echo "✅ PostgreSQL started"
}

stop_env() {
    echo "🛑 Stopping Docker and PostgreSQL..."
    sudo service docker stop 2>/dev/null && echo "✅ Docker stopped"
    sudo service postgresql stop 2>/dev/null && echo "✅ PostgreSQL stopped"
}

install_env() {
    echo "⬇️ Installing missing components..."
    sudo apt update -y

    # Docker
    if ! command -v docker >/dev/null 2>&1; then
        echo "🐳 Installing Docker..."
        sudo apt install -y docker.io
        sudo usermod -aG docker $USER
    fi

    # PostgreSQL
    if ! command -v psql >/dev/null 2>&1; then
        echo "🐘 Installing PostgreSQL..."
        sudo apt install -y postgresql postgresql-contrib
    fi

    # Node.js + npm
    if ! command -v node >/dev/null 2>&1; then
        echo "🟢 Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
        sudo apt install -y nodejs
    fi

    # Prisma
    if ! npx prisma --version >/dev/null 2>&1; then
        echo "🧩 Installing Prisma CLI..."
        npm install -g prisma
    fi

    echo "✅ Installation complete! Restart WSL to apply changes."
}

case "$ACTION" in
    start)
        start_env
        ;;
    stop)
        stop_env
        ;;
    install)
        install_env
        ;;
    *)
        echo "Usage: ./env-control.sh {start|stop|install}"
        ;;
esac
