#!/bin/bash


set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 PROJECT_ID CLUSTER_NAME REGION ENVIRONMENT"
    echo "Example: $0 mxd-network mxd-cluster us-central1 production"
    exit 1
fi

PROJECT_ID=$1
CLUSTER_NAME=$2
REGION=$3
ENVIRONMENT=$4

echo "=== MXD Library GKE Stop Script ==="
echo "Project ID: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Environment: $ENVIRONMENT"
echo

echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

echo "Getting cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION

echo "Stopping MXD application deployment..."
kubectl scale deployment mxd-enterprise-gke --replicas=0 -n mxd-$ENVIRONMENT || echo "Deployment not found or already scaled down"

echo "Stopping monitoring stack..."
kubectl scale deployment prometheus --replicas=0 -n mxd-monitoring || echo "Prometheus deployment not found"
kubectl scale deployment grafana --replicas=0 -n mxd-monitoring || echo "Grafana deployment not found"

echo "Deleting application pods..."
kubectl delete pods --all -n mxd-$ENVIRONMENT || echo "No pods found in mxd-$ENVIRONMENT namespace"

echo "Deleting monitoring pods..."
kubectl delete pods --all -n mxd-monitoring || echo "No pods found in mxd-monitoring namespace"

echo
echo "=== Stop Complete ==="
echo "All deployments have been scaled down to 0 replicas and pods deleted."
echo "The cluster and persistent resources remain available."
echo
echo "To restart the deployment:"
echo "kubectl scale deployment mxd-enterprise-gke --replicas=2 -n mxd-$ENVIRONMENT"
echo "kubectl scale deployment prometheus --replicas=1 -n mxd-monitoring"
echo "kubectl scale deployment grafana --replicas=1 -n mxd-monitoring"
echo
echo "To completely remove all resources, use the clean script:"
echo "bash scripts/clean-gke.sh $PROJECT_ID $CLUSTER_NAME $REGION $ENVIRONMENT"
