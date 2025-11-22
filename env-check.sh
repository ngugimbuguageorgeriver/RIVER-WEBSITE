#!/bin/bash
echo "=========================================="
echo "🧠 DEVELOPMENT ENVIRONMENT HEALTH CHECK"
echo "=========================================="
echo ""

# 1️⃣ Docker
echo "🐳 Checking Docker..."
if command -v docker >/dev/null 2>&1; then
    docker --version
    if docker info >/dev/null 2>&1; then
        echo "✅ Docker is running"
    else
        echo "⚠️ Docker installed but not running"
    fi
else
    echo "❌ Docker not found"
fi
echo ""

# 2️⃣ PostgreSQL
echo "🐘 Checking PostgreSQL..."
if command -v psql >/dev/null 2>&1; then
    psql --version
    sudo service postgresql status >/dev/null 2>&1 && echo "✅ PostgreSQL running" || echo "⚠️ PostgreSQL stopped"
else
    echo "❌ PostgreSQL not found"
fi
echo ""

# 3️⃣ Node.js & npm
echo "🟢 Checking Node.js..."
if command -v node >/dev/null 2>&1; then
    echo "Node: $(node -v)"
    echo "npm: $(npm -v)"
    echo "✅ Node.js and npm installed"
else
    echo "❌ Node.js or npm not found"
fi
echo ""

# 4️⃣ Prisma
echo "🧩 Checking Prisma..."
if command -v npx >/dev/null 2>&1; then
    npx prisma --version >/dev/null 2>&1 && echo "✅ Prisma is installed" || echo "⚠️ Prisma not installed globally"
else
    echo "❌ npm/npx not found"
fi
echo ""

echo "=========================================="
echo "🏁 Health check complete!"
echo "=========================================="
