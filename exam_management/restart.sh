#!/bin/bash
echo "Stopping containers..."
echo "kali" | sudo -S docker-compose down

echo "Removing old containers and volumes..."
echo "kali" | sudo -S docker-compose down -v

echo "Building and starting containers..."
echo "kali" | sudo -S docker-compose up --build -d

echo "Waiting for services to be ready..."
sleep 10

echo "Checking container status..."
echo "kali" | sudo -S docker-compose ps

echo "Checking app logs..."
echo "kali" | sudo -S docker-compose logs app --tail=20
