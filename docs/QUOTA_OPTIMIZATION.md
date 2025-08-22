# GKE Quota Optimization Guide

## Problem
The original GKE deployment configuration exceeded GCP project quotas:
- **CPU Quota**: Required 36 vCPUs, but project limit is 32 vCPUs
- **Storage Quota**: Required 900GB SSD, but project limit is 500GB SSD

## Original Configuration Issues
- Initial cluster: 3 nodes × e2-standard-4 (4 vCPUs each) = 12 vCPUs
- Additional node pool: 3 nodes × e2-standard-4 (4 vCPUs each) = 12 vCPUs
- Autoscaling max: up to 16 total nodes = 64 vCPUs potential
- Storage: 6×100GB node disks + 3×100GB PVCs = 900GB total

## Optimized Solutions

### Solution 1: Small Deployment (Recommended for Development)
**File**: `scripts/deploy-gke-small.sh` and `kubernetes/gke-deployment-small.yaml`

**Resource Usage**:
- **CPU**: 2 nodes × e2-standard-2 (2 vCPUs each) = 4 vCPUs initial, max 8 vCPUs
- **Storage**: 2×50GB node disks + 1×50GB PVC = 150GB total
- **Memory**: 1-2GB per pod, 4GB per node

**Features**:
- Single replica deployment (can scale to 3)
- Standard persistent disks (cost-effective)
- Reduced cache and worker thread counts
- Testnet configuration for development

### Solution 2: Modified Production Deployment
**File**: `scripts/deploy-gke.sh` (updated)

**Resource Usage**:
- **CPU**: 2 nodes × e2-standard-2 (2 vCPUs each) = 4 vCPUs initial, max 12 vCPUs
- **Storage**: 2×50GB node disks + 3×100GB PVCs = 400GB total
- **Memory**: 2-4GB per pod, 4GB per node

**Features**:
- Production-ready with reduced footprint
- Removed redundant node pool
- Standard disks instead of SSD for cost savings
- Maintains 3-replica deployment capability

## Usage Instructions

### For Development/Testing
```bash
# Use the small deployment
./scripts/deploy-gke-small.sh mxd-network mxd-dev-cluster us-central1 development

# Resource usage: ~4-8 vCPUs, ~150GB storage
```

### For Production (Quota-Limited)
```bash
# Use the optimized production deployment
./scripts/deploy-gke.sh mxd-network mxd-cluster us-central1 production

# Resource usage: ~4-12 vCPUs, ~400GB storage
```

## Scaling Considerations

### Horizontal Scaling
- Small deployment: 1-3 replicas
- Production deployment: 1-3 replicas initially, can scale to 6 with cluster autoscaling

### Vertical Scaling
- If more resources needed, consider upgrading to e2-standard-4 nodes
- Monitor CPU and memory usage to determine optimal sizing

### Storage Scaling
- PVCs support volume expansion
- Can increase disk sizes without recreating pods
- Monitor blockchain data growth for storage planning

## Performance Impact

### Expected Performance
- **Small Deployment**: 5-10 TPS, suitable for development and testing
- **Production Deployment**: 10-50 TPS, suitable for moderate production loads

### Monitoring
- Use included Prometheus metrics to monitor resource utilization
- Scale up when CPU consistently >70% or memory >80%
- Monitor disk I/O for storage bottlenecks

## Cost Optimization
- Standard disks vs SSD: ~60% cost reduction
- e2-standard-2 vs e2-standard-4: ~50% cost reduction
- Reduced node count: Significant cost savings

## Migration Path
1. Start with small deployment for testing
2. Validate functionality and performance
3. Upgrade to production deployment when ready
4. Request quota increases if higher performance needed

## Quota Increase Requests
If higher performance is required, request increases for:
- **CPU**: Increase CPUS_ALL_REGIONS quota to 64+ vCPUs
- **Storage**: Increase SSD_TOTAL_GB quota to 1000+ GB

Submit requests at: https://console.cloud.google.com/iam-admin/quotas
