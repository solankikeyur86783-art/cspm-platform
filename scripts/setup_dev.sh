#!/bin/bash
set -e

echo "🛡️  CSPM Platform — Dev Setup"
echo "================================"

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "❌ Docker required. Install from https://docker.com"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3.11+ required"; exit 1; }

echo "✅ Prerequisites OK"

# Copy env file
if [ ! -f backend/.env ]; then
    cp backend/.env.example backend/.env
    echo "📋 Created backend/.env from .env.example — fill in your cloud credentials"
fi

# Create logs dir
mkdir -p logs

# Start infra containers (Postgres + Redis only)
echo "🐳 Starting PostgreSQL and Redis..."
docker compose up postgres redis -d

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Install Python deps
echo "📦 Installing Python dependencies..."
cd backend
pip install -r requirements.txt --quiet

# Run migrations
echo "🗄️  Running database migrations..."
alembic upgrade head

# Seed CIS rules
echo "🌱 Seeding CIS benchmark rules..."
python -c "
import asyncio
from app.core.database import init_db
asyncio.run(init_db())
print('Database initialized')
"

cd ..
echo ""
echo "✅ Setup complete!"
echo ""
echo "Start the API:     make dev"
echo "Start workers:     make worker-scans"
echo "Run tests:         make test"
echo "Open docs:         http://localhost:8000/docs"
echo "Open pgAdmin:      http://localhost:5050 (admin@cspm.local / admin)"
echo "Open Flower:       http://localhost:5555"
