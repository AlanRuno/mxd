#!/bin/bash

set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 PROJECT_ID CLUSTER_NAME REGION ENVIRONMENT"
    echo "Example: $0 mxd-network mxd-test-cluster us-central1 testing"
    exit 1
fi

PROJECT_ID=$1
CLUSTER_NAME=$2
REGION=$3
ENVIRONMENT=$4

echo "=== MXD Library GKE Test Deployment ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "Image Tag: latest"
echo "NOTE: This is an ultra-minimal deployment for testing (shared cores, minimal resources)"

echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

echo "Enabling required GCP APIs..."
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com

if ! gcloud container clusters describe $CLUSTER_NAME --region=$REGION >/dev/null 2>&1; then
    echo "Creating minimal GKE test cluster..."
    
    MAX_RETRIES=3
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        echo "Attempt $((RETRY_COUNT + 1)) of $MAX_RETRIES to create cluster..."
        
        if gcloud container clusters create $CLUSTER_NAME \
            --region=$REGION \
            --num-nodes=1 \
            --min-nodes=1 \
            --max-nodes=2 \
            --enable-autoscaling \
            --machine-type=e2-micro \
            --disk-size=20GB \
            --disk-type=pd-standard \
            --enable-autorepair \
            --enable-autoupgrade \
            --enable-network-policy \
            --enable-ip-alias \
            --logging=SYSTEM \
            --monitoring=SYSTEM \
            --addons=HorizontalPodAutoscaling,HttpLoadBalancing,NetworkPolicy \
            --node-labels=environment=$ENVIRONMENT,tier=testing \
            --preemptible; then
            echo "Test cluster created successfully!"
            break
        else
            RETRY_COUNT=$((RETRY_COUNT + 1))
            if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
                echo "Cluster creation failed. Waiting 30 seconds before retry..."
                sleep 30
            else
                echo "ERROR: Failed to create cluster after $MAX_RETRIES attempts"
                echo "This may be due to:"
                echo "  - Metadata server connectivity issues"
                echo "  - Quota limitations"
                echo "  - Network connectivity problems"
                echo "Please check your GCP project quotas and network connectivity"
                exit 1
            fi
        fi
    done
else
    echo "GKE cluster $CLUSTER_NAME already exists"
fi

echo "Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION

echo "Configuring firewall rules for MXD test application..."

echo "Creating firewall rule for MXD P2P communication (port 8000)..."
gcloud compute firewall-rules create mxd-p2p-$ENVIRONMENT \
    --description="Allow MXD P2P communication between test nodes" \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:8000 \
    --source-ranges=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
    --target-tags=gke-$CLUSTER_NAME-node || echo "P2P firewall rule already exists"

echo "Creating firewall rule for MXD health/metrics endpoints (port 8080)..."
gcloud compute firewall-rules create mxd-health-metrics-$ENVIRONMENT \
    --description="Allow access to MXD health and metrics endpoints" \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:8080 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=gke-$CLUSTER_NAME-node || echo "Health/metrics firewall rule already exists"

echo "Creating firewall rule for LoadBalancer health checks..."
gcloud compute firewall-rules create mxd-lb-health-checks-$ENVIRONMENT \
    --description="Allow GCP LoadBalancer health checks" \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:8080,tcp:8000 \
    --source-ranges=35.191.0.0/16,130.211.0.0/22 \
    --target-tags=gke-$CLUSTER_NAME-node || echo "LoadBalancer health check firewall rule already exists"

echo "Creating storage classes..."
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard-retain
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-standard
  replication-type: none
reclaimPolicy: Retain
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
EOF

echo "Building and pushing Docker image..."
docker build -t gcr.io/$PROJECT_ID/mxdlib:latest .
docker push gcr.io/$PROJECT_ID/mxdlib:latest

echo "Creating namespace..."
kubectl create namespace mxd-$ENVIRONMENT || echo "Namespace already exists"

echo "Applying Kubernetes manifests..."
envsubst < kubernetes/gke-deployment-test.yaml | kubectl apply -f -

echo "Creating static IP..."
gcloud compute addresses create mxd-ip-test --global || echo "Static IP already exists"

echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=600s deployment/mxd-enterprise-gke-test -n mxd-$ENVIRONMENT

echo "Getting service information..."
kubectl get services -n mxd-$ENVIRONMENT

echo "External Load Balancer IP:"
kubectl get service mxd-service-external-test -n mxd-$ENVIRONMENT -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
echo

echo
echo "=== Test Deployment Complete ==="
echo "Access your MXD test node:"
echo "Health endpoint: http://\$(kubectl get service mxd-service-external-test -n mxd-$ENVIRONMENT -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):8080/health"
echo "Metrics endpoint: http://\$(kubectl get service mxd-service-external-test -n mxd-$ENVIRONMENT -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):8080/metrics"
echo
echo "To check deployment status:"
echo "kubectl get pods -n mxd-$ENVIRONMENT"
echo "kubectl logs -f deployment/mxd-enterprise-gke-test -n mxd-$ENVIRONMENT"
echo
echo "To scale the deployment:"
echo "kubectl scale deployment mxd-enterprise-gke-test --replicas=2 -n mxd-$ENVIRONMENT"

echo
echo "=== Firewall Rules Summary ==="
echo "Created firewall rules:"
echo "  - mxd-p2p-$ENVIRONMENT: P2P communication (port 8000, private networks)"
echo "  - mxd-health-metrics-$ENVIRONMENT: Health/metrics endpoints (port 8080, public)"
echo "  - mxd-lb-health-checks-$ENVIRONMENT: LoadBalancer health checks (GCP ranges)"
echo
echo "To view firewall rules:"
echo "gcloud compute firewall-rules list --filter=\"name~mxd-.*-$ENVIRONMENT\""
echo
echo "To delete firewall rules (cleanup):"
echo "gcloud compute firewall-rules delete mxd-p2p-$ENVIRONMENT mxd-health-metrics-$ENVIRONMENT mxd-lb-health-checks-$ENVIRONMENT --quiet"

echo
echo "Test deployment completed successfully!"
echo "Resource usage: ~0.25-2 vCPUs (shared), ~1GB RAM, ~30GB storage"
echo "Cost: Ultra-minimal (preemptible e2-micro instances)"
