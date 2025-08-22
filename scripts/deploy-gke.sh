#!/bin/bash

set -e


PROJECT_ID=${1:-"your-gcp-project"}
CLUSTER_NAME=${2:-"mxd-cluster"}
REGION=${3:-"us-central1"}
ENVIRONMENT=${4:-"production"}
IMAGE_TAG=${5:-"latest"}

echo "=== MXD Library GKE Deployment ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "Image Tag: $IMAGE_TAG"
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
    echo "Creating GKE cluster..."
    gcloud container clusters create $CLUSTER_NAME \
        --region=$REGION \
        --num-nodes=3 \
        --min-nodes=1 \
        --max-nodes=10 \
        --enable-autoscaling \
        --machine-type=e2-standard-4 \
        --disk-size=100GB \
        --disk-type=pd-ssd \
        --enable-autorepair \
        --enable-autoupgrade \
        --enable-network-policy \
        --enable-ip-alias \
        --enable-stackdriver-kubernetes \
        --addons=HorizontalPodAutoscaling,HttpLoadBalancing,NetworkPolicy \
        --node-labels=environment=$ENVIRONMENT \
        --node-taints=dedicated=mxd:NoSchedule
    
    gcloud container node-pools create mxd-node-pool \
        --cluster=$CLUSTER_NAME \
        --region=$REGION \
        --num-nodes=3 \
        --min-nodes=1 \
        --max-nodes=6 \
        --enable-autoscaling \
        --machine-type=e2-standard-4 \
        --disk-size=100GB \
        --disk-type=pd-ssd \
        --node-labels=workload=mxd-enterprise \
        --node-taints=dedicated=mxd:NoSchedule
else
    echo "GKE cluster $CLUSTER_NAME already exists"
fi

echo "Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION

echo "Creating storage classes..."
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ssd-retain
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-ssd
  replication-type: regional-pd
reclaimPolicy: Retain
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
EOF

echo "Building and pushing Docker image..."
docker build -t gcr.io/$PROJECT_ID/mxdlib:$IMAGE_TAG .

gcloud auth configure-docker

docker push gcr.io/$PROJECT_ID/mxdlib:$IMAGE_TAG

kubectl create namespace mxd-$ENVIRONMENT --dry-run=client -o yaml | kubectl apply -f -

sed "s/PROJECT_ID/$PROJECT_ID/g" kubernetes/gke-deployment.yaml > /tmp/gke-deployment-$ENVIRONMENT.yaml
sed -i "s/BUCKET_NAME/$PROJECT_ID-mxd-backups/g" /tmp/gke-deployment-$ENVIRONMENT.yaml

echo "Applying Kubernetes manifests..."
kubectl apply -f /tmp/gke-deployment-$ENVIRONMENT.yaml -n mxd-$ENVIRONMENT

echo "Setting up monitoring..."
kubectl apply -f kubernetes/gke-monitoring.yaml

echo "Creating static IP..."
gcloud compute addresses create mxd-ip --global || echo "Static IP already exists"

echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/mxd-enterprise-gke -n mxd-$ENVIRONMENT

echo
echo "=== Deployment Complete ==="
echo "Getting service information..."
kubectl get services -n mxd-$ENVIRONMENT
kubectl get ingress -n mxd-$ENVIRONMENT

echo
echo "External Load Balancer IP:"
kubectl get service mxd-service-external -n mxd-$ENVIRONMENT -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
echo

echo
echo "Monitoring URLs:"
echo "Prometheus: http://$(kubectl get service prometheus-service -n mxd-monitoring -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):9090"
echo "Grafana: http://$(kubectl get service grafana-service -n mxd-monitoring -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):3000"
echo "Default Grafana credentials: admin/admin123 (CHANGE THIS!)"

echo
echo "To check deployment status:"
echo "kubectl get pods -n mxd-$ENVIRONMENT"
echo "kubectl logs -f deployment/mxd-enterprise-gke -n mxd-$ENVIRONMENT"

echo
echo "To scale deployment:"
echo "kubectl scale deployment mxd-enterprise-gke --replicas=5 -n mxd-$ENVIRONMENT"

echo
echo "Deployment completed successfully!"
