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

echo "=== MXD Library GKE Test Stop Script ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo "NOTE: This is for the ultra-minimal test deployment"
echo

echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

echo "Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION

echo "Stopping MXD test application deployment..."
kubectl scale deployment mxd-enterprise-gke-test --replicas=0 -n mxd-$ENVIRONMENT || echo "Deployment not found or already scaled down"

echo "Deleting application pods..."
kubectl delete pods --all -n mxd-$ENVIRONMENT || echo "No pods found in mxd-$ENVIRONMENT namespace"

echo
echo "=== Test Stop Complete ==="
echo "All deployments have been scaled down to 0 replicas and pods deleted."
echo "The cluster and persistent resources remain available."
echo
echo "To restart the deployment:"
echo "kubectl scale deployment mxd-enterprise-gke-test --replicas=1 -n mxd-$ENVIRONMENT"
echo
echo "To completely remove all resources, use the clean script:"
echo "bash scripts/clean-gke-test.sh $PROJECT_ID $CLUSTER_NAME $REGION $ENVIRONMENT"
