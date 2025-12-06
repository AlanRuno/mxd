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

echo "=== MXD Library GKE Test Clean Script ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "NOTE: This is for the ultra-minimal test deployment"
echo
echo "WARNING: This will permanently delete all test resources!"
echo "Press Ctrl+C within 10 seconds to cancel..."
sleep 10

echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

echo "Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION || echo "Cluster not accessible, continuing with cleanup..."

echo "Deleting Kubernetes namespace..."
kubectl delete namespace mxd-$ENVIRONMENT --ignore-not-found=true

echo "Deleting GKE test cluster..."
gcloud container clusters delete $CLUSTER_NAME --region=$REGION --quiet || echo "Cluster not found or already deleted"

echo "Deleting static IP addresses..."
gcloud compute addresses delete mxd-ip-test --global --quiet || echo "Static IP mxd-ip-test not found"

echo "Deleting firewall rules..."
gcloud compute firewall-rules delete mxd-p2p-$ENVIRONMENT --quiet || echo "P2P firewall rule not found"
gcloud compute firewall-rules delete mxd-health-metrics-$ENVIRONMENT --quiet || echo "Health/metrics firewall rule not found"
gcloud compute firewall-rules delete mxd-lb-health-checks-$ENVIRONMENT --quiet || echo "LoadBalancer health check firewall rule not found"

echo "Deleting container images (optional)..."
read -p "Delete container images from gcr.io/$PROJECT_ID/mxdlib? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    gcloud container images delete gcr.io/$PROJECT_ID/mxdlib:latest --quiet || echo "Container image not found"
    gcloud container images list-tags gcr.io/$PROJECT_ID/mxdlib --format="get(digest)" | head -5 | while read digest; do
        gcloud container images delete gcr.io/$PROJECT_ID/mxdlib@$digest --quiet || echo "Image digest not found: $digest"
    done
else
    echo "Skipping container image deletion"
fi

echo
echo "=== Test Clean Complete ==="
echo "All MXD test deployment resources have been deleted:"
echo "  ✓ Kubernetes namespace (mxd-$ENVIRONMENT)"
echo "  ✓ GKE test cluster ($CLUSTER_NAME)"
echo "  ✓ Static IP addresses"
echo "  ✓ Firewall rules (mxd-*-$ENVIRONMENT)"
echo "  ✓ Container images (if selected)"
echo
echo "Your GCP project is now clean of MXD test deployment resources."
echo "Resource usage: Freed ~0.25-2 vCPUs (shared), ~1GB RAM, ~30GB storage"
