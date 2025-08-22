#!/bin/bash

set -e

echo "Setting up MXD monitoring infrastructure..."

mkdir -p monitoring/grafana/{dashboards,datasources}
mkdir -p monitoring/prometheus

echo "Starting Prometheus and Grafana..."
docker-compose -f docker-compose.test.yml up -d prometheus grafana

echo "Waiting for services to start..."
sleep 30

if curl -f http://localhost:9090/-/healthy; then
    echo "✓ Prometheus is running"
else
    echo "✗ Prometheus failed to start"
    exit 1
fi

if curl -f http://localhost:3000/api/health; then
    echo "✓ Grafana is running"
else
    echo "✗ Grafana failed to start"
    exit 1
fi

echo "Monitoring setup completed!"
echo "Access Grafana at: http://localhost:3000 (admin/admin)"
echo "Access Prometheus at: http://localhost:9090"
