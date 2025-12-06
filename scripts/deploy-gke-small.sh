#!/bin/bash

set -e

PROJECT_ID=${1:-"your-gcp-project"}
CLUSTER_NAME=${2:-"mxd-cluster-small"}
REGION=${3:-"us-central1"}
ENVIRONMENT=${4:-"development"}
IMAGE_TAG=${5:-"latest"}

echo "=== MXD Library GKE Small Deployment ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "Image Tag: $IMAGE_TAG"
echo "NOTE: This is a quota-optimized deployment for development/testing"
echo

command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI is required but not installed. Aborting." >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required but not installed. Aborting." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }

echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

echo "Enabling required GCP APIs..."
gcloud services enable container.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable compute.googleapis.com

if ! gcloud container clusters describe $CLUSTER_NAME --region=$REGION >/dev/null 2>&1; then
    echo "Creating small GKE cluster (quota-optimized)..."
    
    MAX_RETRIES=3
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        echo "Attempt $((RETRY_COUNT + 1)) of $MAX_RETRIES to create cluster..."
        
        if gcloud container clusters create $CLUSTER_NAME \
            --region=$REGION \
            --num-nodes=2 \
            --min-nodes=1 \
            --max-nodes=4 \
            --enable-autoscaling \
            --machine-type=e2-standard-2 \
            --disk-size=50GB \
            --disk-type=pd-standard \
            --enable-autorepair \
            --enable-autoupgrade \
            --enable-network-policy \
            --enable-ip-alias \
            --logging=SYSTEM,WORKLOAD,API_SERVER \
            --monitoring=SYSTEM \
            --addons=HorizontalPodAutoscaling,HttpLoadBalancing,NetworkPolicy \
            --node-labels=environment=$ENVIRONMENT; then
            echo "Cluster created successfully!"
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

echo "Configuring firewall rules for MXD application..."

echo "Creating firewall rule for MXD P2P communication (port 8000)..."
gcloud compute firewall-rules create mxd-p2p-$ENVIRONMENT \
    --description="Allow MXD P2P communication between nodes" \
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
docker build -t gcr.io/$PROJECT_ID/mxdlib:$IMAGE_TAG .

gcloud auth configure-docker

docker push gcr.io/$PROJECT_ID/mxdlib:$IMAGE_TAG

kubectl create namespace mxd-$ENVIRONMENT --dry-run=client -o yaml | kubectl apply -f -

sed "s/PROJECT_ID/$PROJECT_ID/g" kubernetes/gke-deployment-small.yaml > /tmp/gke-deployment-small-$ENVIRONMENT.yaml
sed -i "s/BUCKET_NAME/$PROJECT_ID-mxd-backups/g" /tmp/gke-deployment-small-$ENVIRONMENT.yaml

echo "Applying Kubernetes manifests..."
kubectl apply -f /tmp/gke-deployment-small-$ENVIRONMENT.yaml -n mxd-$ENVIRONMENT

echo "Creating static IP..."
gcloud compute addresses create mxd-ip-small --global || echo "Static IP already exists"

echo "Creating firewall rules for monitoring stack (if deployed)..."
gcloud compute firewall-rules create mxd-monitoring-$ENVIRONMENT \
    --description="Allow access to Prometheus and Grafana monitoring" \
    --direction=INGRESS \
    --priority=1000 \
    --network=default \
    --action=ALLOW \
    --rules=tcp:3000,tcp:9090 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=gke-$CLUSTER_NAME-node || echo "Monitoring firewall rule already exists"

echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/mxd-enterprise-gke-small -n mxd-$ENVIRONMENT

echo
echo "=== Small Deployment Complete ==="
echo "Getting service information..."
kubectl get services -n mxd-$ENVIRONMENT
kubectl get ingress -n mxd-$ENVIRONMENT

echo
echo "External Load Balancer IP:"
kubectl get service mxd-service-external-small -n mxd-$ENVIRONMENT -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
echo

echo
echo "To check deployment status:"
echo "kubectl get pods -n mxd-$ENVIRONMENT"
echo "kubectl logs -f deployment/mxd-enterprise-gke-small -n mxd-$ENVIRONMENT"

echo
echo "To scale deployment:"
echo "kubectl scale deployment mxd-enterprise-gke-small --replicas=3 -n mxd-$ENVIRONMENT"

echo
echo "=== Firewall Rules Summary ==="
echo "Created firewall rules:"
echo "  - mxd-p2p-$ENVIRONMENT: P2P communication (port 8000, private networks)"
echo "  - mxd-health-metrics-$ENVIRONMENT: Health/metrics endpoints (port 8080, public)"
echo "  - mxd-lb-health-checks-$ENVIRONMENT: LoadBalancer health checks (GCP ranges)"
echo "  - mxd-monitoring-$ENVIRONMENT: Monitoring stack (ports 3000, 9090, public)"
echo
echo "To view firewall rules:"
echo "gcloud compute firewall-rules list --filter=\"name~mxd-.*-$ENVIRONMENT\""
echo
echo "To delete firewall rules (cleanup):"
echo "gcloud compute firewall-rules delete mxd-p2p-$ENVIRONMENT mxd-health-metrics-$ENVIRONMENT mxd-lb-health-checks-$ENVIRONMENT mxd-monitoring-$ENVIRONMENT --quiet"

echo
echo "Small deployment completed successfully!"
echo "Resource usage: ~4-8 vCPUs, ~200GB storage"
