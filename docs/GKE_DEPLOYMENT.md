# MXD Library - Google Kubernetes Engine (GKE) Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the MXD Universal Dynamic Library on Google Kubernetes Engine (GKE) with production-ready configurations, monitoring, and security.

## Prerequisites

### Required Tools
- Google Cloud SDK (`gcloud`)
- Kubernetes CLI (`kubectl`) 
- Docker
- Git

### GCP Setup
1. **Create or select a GCP project**
2. **Enable billing** for the project
3. **Enable required APIs**:
   - Kubernetes Engine API
   - Container Registry API
   - Compute Engine API

### Install Tools
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Install kubectl
gcloud components install kubectl

# Verify installations
gcloud version
kubectl version --client
docker --version
```

## Quick Deployment

### Automated Deployment
```bash
# Clone repository
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib

# Run automated GKE deployment
./scripts/deploy-gke.sh YOUR_PROJECT_ID mxd-cluster us-central1 production

# Monitor deployment
kubectl get pods -n mxd-production -w
```

### Manual Step-by-Step Deployment

#### 1. Authenticate and Configure GCP
```bash
# Authenticate with Google Cloud
gcloud auth login

# Set your project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable compute.googleapis.com
```

#### 2. Create GKE Cluster
```bash
# Create production-ready cluster
gcloud container clusters create mxd-cluster \
    --region=us-central1 \
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
    --addons=HorizontalPodAutoscaling,HttpLoadBalancing,NetworkPolicy

# Get cluster credentials
gcloud container clusters get-credentials mxd-cluster --region=us-central1
```

#### 3. Build and Push Docker Image
```bash
# Build MXD library image
docker build -t gcr.io/YOUR_PROJECT_ID/mxdlib:latest .

# Configure Docker for GCR
gcloud auth configure-docker

# Push image to Google Container Registry
docker push gcr.io/YOUR_PROJECT_ID/mxdlib:latest
```

#### 4. Deploy to Kubernetes
```bash
# Update deployment with your project ID
sed -i 's/PROJECT_ID/YOUR_PROJECT_ID/g' kubernetes/gke-deployment.yaml

# Apply storage classes
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
EOF

# Deploy MXD application
kubectl apply -f kubernetes/gke-deployment.yaml

# Deploy monitoring stack
kubectl apply -f kubernetes/gke-monitoring.yaml
```

#### 5. Verify Deployment
```bash
# Check pod status
kubectl get pods -l app=mxd-enterprise

# Check services
kubectl get services

# View logs
kubectl logs -f deployment/mxd-enterprise-gke

# Test health endpoint
kubectl port-forward service/mxd-service-external 8080:8080 &
curl http://localhost:8080/health
```

## Configuration

### Environment Variables
Key environment variables for GKE deployment:

| Variable | Description | Default |
|----------|-------------|---------|
| `MXD_NODE_ID` | Unique node identifier | Pod name |
| `MXD_NETWORK_MAGIC` | Network magic number | `0x4D584431` |
| `MXD_LOG_LEVEL` | Logging level | `INFO` |
| `MXD_METRICS_PORT` | Metrics endpoint port | `8080` |
| `GOOGLE_CLOUD_PROJECT` | GCP project ID | Auto-detected |

### Resource Requirements

#### Minimum Requirements (per pod)
- **CPU**: 1 core
- **Memory**: 2GB
- **Storage**: 100GB SSD

#### Recommended Production
- **CPU**: 2 cores
- **Memory**: 4GB
- **Storage**: 100GB SSD (regional persistent disk)
- **Replicas**: 3 (for high availability)

### Storage Configuration
```yaml
# High-performance SSD storage class
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
```

## Monitoring and Observability

### Prometheus Metrics
The deployment includes Prometheus monitoring with the following metrics:
- Node performance (TPS, latency)
- Network connectivity
- Resource utilization
- Blockchain synchronization status

### Grafana Dashboards
Access Grafana at the external IP provided after deployment:
- **Default credentials**: admin/admin123 (change immediately)
- **Pre-configured dashboards** for MXD metrics
- **Alerting** for critical thresholds

### Logging
Structured logging is enabled with:
- **Google Cloud Logging** integration
- **JSON format** for easy parsing
- **Log levels**: DEBUG, INFO, WARN, ERROR

## Security

### Network Security
- **Network policies** restrict pod-to-pod communication
- **Private cluster** option available
- **Firewall rules** for external access

### Pod Security
- **Non-root user** execution
- **Security contexts** with restricted privileges
- **Resource limits** to prevent resource exhaustion

### Secrets Management
```bash
# Create secrets for sensitive data
kubectl create secret generic mxd-secrets \
    --from-literal=network-magic="0x4D584431" \
    --from-literal=crypto-salt="your-secure-salt"
```

## Scaling

### Horizontal Pod Autoscaling
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mxd-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mxd-enterprise-gke
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Cluster Autoscaling
The cluster is configured with autoscaling (1-10 nodes) to handle varying loads.

## Load Balancing

### External Load Balancer
- **Google Cloud Load Balancer** for external traffic
- **Health checks** on `/health` endpoint
- **SSL termination** with managed certificates

### Internal Load Balancer
- **ClusterIP service** for internal communication
- **Service mesh** ready (Istio compatible)

## Backup and Disaster Recovery

### Persistent Volume Backups
```bash
# Create volume snapshot
gcloud compute disks snapshot DISK_NAME \
    --snapshot-names=mxd-backup-$(date +%Y%m%d-%H%M%S) \
    --zone=ZONE
```

### Database Backups
- **Automated backups** every 6 hours
- **30-day retention** policy
- **Cross-region replication** available

## Troubleshooting

### Common Issues

#### Pod Startup Issues
```bash
# Check pod events
kubectl describe pod POD_NAME

# View container logs
kubectl logs POD_NAME -c mxd-node

# Check resource constraints
kubectl top pods
```

#### Network Connectivity
```bash
# Test internal connectivity
kubectl exec -it POD_NAME -- curl http://mxd-service-internal:8080/health

# Check service endpoints
kubectl get endpoints
```

#### Storage Issues
```bash
# Check PVC status
kubectl get pvc

# View storage events
kubectl describe pvc mxd-data-gke
```

### Performance Tuning

#### Node Pool Optimization
```bash
# Create optimized node pool
gcloud container node-pools create mxd-optimized \
    --cluster=mxd-cluster \
    --machine-type=c2-standard-8 \
    --disk-type=pd-ssd \
    --disk-size=200GB \
    --enable-autoscaling \
    --max-nodes=5
```

#### Resource Optimization
- **CPU requests/limits** based on actual usage
- **Memory optimization** for blockchain data
- **Storage IOPS** tuning for high-throughput scenarios

## Cost Optimization

### Preemptible Nodes
```bash
# Create cost-effective node pool
gcloud container node-pools create mxd-preemptible \
    --cluster=mxd-cluster \
    --preemptible \
    --machine-type=e2-standard-4 \
    --num-nodes=2
```

### Resource Management
- **Vertical Pod Autoscaling** for right-sizing
- **Cluster autoscaling** to minimize idle resources
- **Scheduled scaling** for predictable workloads

## Maintenance

### Updates and Upgrades
```bash
# Update cluster
gcloud container clusters upgrade mxd-cluster --region=us-central1

# Update node pools
gcloud container node-pools upgrade mxd-node-pool \
    --cluster=mxd-cluster --region=us-central1

# Rolling update deployment
kubectl set image deployment/mxd-enterprise-gke \
    mxd-node=gcr.io/PROJECT_ID/mxdlib:v2.0.0
```

### Health Monitoring
- **Uptime checks** for external endpoints
- **SLA monitoring** with alerting
- **Performance baselines** and anomaly detection

## Support and Documentation

### Additional Resources
- [MXD Library Documentation](../README.md)
- [Enterprise Deployment Guide](ENTERPRISE_DEPLOYMENT.md)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [GKE Documentation](https://cloud.google.com/kubernetes-engine/docs)

### Getting Help
- **GitHub Issues**: Report bugs and feature requests
- **Community Support**: Join the MXD community discussions
- **Enterprise Support**: Contact for production support

---

**Note**: Replace `YOUR_PROJECT_ID` with your actual Google Cloud project ID throughout this guide.
