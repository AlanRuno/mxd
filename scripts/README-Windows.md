# Windows Local Kubernetes Deployment Scripts

This directory contains PowerShell scripts for deploying the MXD blockchain application locally on Windows using Docker Desktop with Kubernetes.

## Prerequisites

1. **Docker Desktop for Windows**
   - Download from: https://www.docker.com/products/docker-desktop/
   - Install and start Docker Desktop
   - Enable Kubernetes in Docker Desktop settings:
     - Open Docker Desktop
     - Go to Settings → Kubernetes
     - Check "Enable Kubernetes"
     - Click "Apply & Restart"

2. **PowerShell 5.1 or later**
   - Included with Windows 10/11
   - Or install PowerShell 7+ from: https://github.com/PowerShell/PowerShell

## Scripts Overview

### `deploy-local-windows.ps1`
Deploys the MXD application locally on Kubernetes using Docker Desktop.

**Usage:**
```powershell
.\scripts\deploy-local-windows.ps1 -Environment "local" -ImageTag "latest"
```

**Parameters:**
- `-Environment`: Deployment environment name (default: "local")
- `-ImageTag`: Docker image tag to use (default: "latest")
- `-SkipDockerCheck`: Skip Docker/Kubernetes prerequisite checks

**What it does:**
- Checks Docker Desktop and Kubernetes prerequisites
- Builds the MXD Docker image locally
- Creates Kubernetes namespace and resources
- Deploys the MXD node with health endpoints
- Configures NodePort services for local access

### `stop-local-windows.ps1`
Gracefully stops the local MXD deployment without removing persistent data.

**Usage:**
```powershell
.\scripts\stop-local-windows.ps1 -Environment "local"
```

**What it does:**
- Scales deployment to 0 replicas
- Deletes running pods
- Preserves persistent volumes and configuration

### `update-local-windows.ps1`
Updates an existing local MXD deployment to the latest runtime version.

**Usage:**
```powershell
.\scripts\update-local-windows.ps1 -Environment "local" -ImageTag "latest"
```

**Parameters:**
- `-Environment`: Deployment environment name (default: "local")
- `-ImageTag`: Docker image tag to use (default: "latest")
- `-SkipDockerCheck`: Skip Docker/Kubernetes prerequisite checks
- `-Force`: Skip confirmation prompt

**What it does:**
- Checks for existing deployment in the specified environment
- Rebuilds the MXD Docker image with latest code
- Performs rolling update of Kubernetes deployment
- Waits for rollout completion and verifies endpoints
- Provides rollback instructions if needed

### `clean-local-windows.ps1`
Completely removes all MXD deployment resources and optionally Docker images.

**Usage:**
```powershell
.\scripts\clean-local-windows.ps1 -Environment "local" -Force
```

**Parameters:**
- `-Environment`: Environment to clean (default: "local")
- `-Force`: Skip confirmation prompt

**What it does:**
- Deletes entire Kubernetes namespace
- Removes all deployments, services, pods
- Deletes persistent volumes and data
- Optionally removes Docker images

## Quick Start

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/AlanRuno/mxdlib.git
   cd mxdlib
   ```

2. **Deploy locally:**
   ```powershell
   .\scripts\deploy-local-windows.ps1
   ```

3. **Access the application:**
   - Health endpoint: http://localhost:30080/health
   - Metrics endpoint: http://localhost:30080/metrics
   - P2P port: localhost:30000

4. **Monitor the deployment:**
   ```powershell
   kubectl get pods -n mxd-local
   kubectl logs -f deployment/mxd-enterprise-local -n mxd-local
   ```

5. **Update to latest version:**
   ```powershell
   .\scripts\update-local-windows.ps1
   ```

6. **Stop when done:**
   ```powershell
   .\scripts\stop-local-windows.ps1
   ```

7. **Clean up completely:**
   ```powershell
   .\scripts\clean-local-windows.ps1
   ```

## Troubleshooting

### Docker Desktop Issues
- Ensure Docker Desktop is running
- Check that Kubernetes is enabled in settings
- Restart Docker Desktop if needed

### Kubernetes Context Issues
```powershell
kubectl config get-contexts
kubectl config use-context docker-desktop
```

### Port Conflicts
If ports 30000 or 30080 are in use, modify the NodePort values in the deployment script.

### Image Build Issues
```powershell
docker build -t mxdlib:latest .
docker images | grep mxdlib
```

### Pod Not Starting
```powershell
kubectl describe pod -n mxd-local
kubectl logs -f deployment/mxd-enterprise-local -n mxd-local
```

### Update Issues
```powershell
# Check rollout status
kubectl rollout status deployment/mxd-enterprise-local -n mxd-local

# View rollout history
kubectl rollout history deployment/mxd-enterprise-local -n mxd-local

# Rollback if needed
kubectl rollout undo deployment/mxd-enterprise-local -n mxd-local

# Force restart if stuck
kubectl delete pods --all -n mxd-local
```

### Image Build Issues During Update
```powershell
# Clean Docker build cache
docker system prune -f

# Rebuild with no cache
docker build --no-cache -t mxdlib:latest .
```

## Resource Usage

The local deployment uses:
- **CPU**: 250m-500m per pod
- **Memory**: 512Mi-1Gi per pod
- **Storage**: 20Gi persistent volume
- **Ports**: 30000 (P2P), 30080 (HTTP)

## Security Notes

- This deployment is for local development/testing only
- Services are exposed via NodePort for easy access
- No authentication or encryption is configured
- Data is stored in local persistent volumes

## Advanced Usage

### Multiple Environments
```powershell
.\scripts\deploy-local-windows.ps1 -Environment "dev"
.\scripts\deploy-local-windows.ps1 -Environment "test"
```

### Custom Image Tags
```powershell
.\scripts\deploy-local-windows.ps1 -ImageTag "v1.0.0"
```

### Scaling
```powershell
kubectl scale deployment mxd-enterprise-local --replicas=2 -n mxd-local
```

### Port Forwarding (Alternative to NodePort)
```powershell
kubectl port-forward deployment/mxd-enterprise-local 8080:8080 -n mxd-local
```
