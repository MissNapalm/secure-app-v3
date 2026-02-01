#!/bin/bash

echo "🐦 Twitter Clone - Quick Start Script"
echo "======================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Please install Go 1.21 or higher."
    echo "Visit: https://golang.org/doc/install"
    exit 1
fi

echo "✅ Docker and Go found!"
echo ""

# Start PostgreSQL
echo "📦 Starting PostgreSQL with Docker..."
docker-compose up -d

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Check if PostgreSQL is ready
until docker exec twitter-clone-db pg_isready -U postgres &> /dev/null; do
    echo "⏳ Still waiting for PostgreSQL..."
    sleep 2
done

echo "✅ PostgreSQL is ready!"
echo ""

# Install Go dependencies
echo "📥 Installing Go dependencies..."
cd backend
go mod download
echo "✅ Dependencies installed!"
echo ""

# Run the application
echo "🚀 Starting the application..."
echo ""
echo "The app will be available at: http://localhost:8080"
echo "MFA codes will appear in this terminal."
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

go run main.go
