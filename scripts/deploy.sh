#!/bin/bash

set -e

ENVIRONMENT=${1:-staging}
VERSION=${2:-latest}

echo "Deploying MXD Library to $ENVIRONMENT environment (version: $VERSION)"

case $ENVIRONMENT in
    "staging")
        REGISTRY="staging.mxd.network"
        NAMESPACE="mxd-staging"
        ;;
    "production")
        REGISTRY="registry.mxd.network"
        NAMESPACE="mxd-production"
        ;;
    "local")
        echo "Local deployment mode"
        REGISTRY="localhost:5000"
        NAMESPACE="default"
        ;;
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

echo "Building Docker image..."
docker build -t $REGISTRY/mxdlib:$VERSION .

if [ "$ENVIRONMENT" != "local" ]; then
    echo "Running security scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy image --exit-code 1 --severity HIGH,CRITICAL \
        $REGISTRY/mxdlib:$VERSION

    echo "Pushing image to registry..."
    docker push $REGISTRY/mxdlib:$VERSION

    echo "Deploying to Kubernetes..."
    kubectl set image deployment/mxd-enterprise mxd-node=$REGISTRY/mxdlib:$VERSION -n $NAMESPACE

    echo "Waiting for rollout to complete..."
    kubectl rollout status deployment/mxd-enterprise -n $NAMESPACE --timeout=300s

    echo "Running health checks..."
    kubectl wait --for=condition=ready pod -l app=mxd-enterprise -n $NAMESPACE --timeout=120s

    echo "Running smoke tests..."
    HEALTH_URL="https://api-$ENVIRONMENT.mxd.network/health"
    curl -f $HEALTH_URL || (echo "Health check failed!" && exit 1)
else
    echo "Starting local deployment..."
    docker run -d --name mxd-enterprise-local \
        -p 8000:8000 -p 8080:8080 \
        -e MXD_LOG_LEVEL=INFO \
        $REGISTRY/mxdlib:$VERSION
    
    echo "Waiting for container to be ready..."
    sleep 10
    
    echo "Running local health check..."
    curl -f http://localhost:8080/health || (echo "Local health check failed!" && exit 1)
fi

echo "Deployment completed successfully!"
