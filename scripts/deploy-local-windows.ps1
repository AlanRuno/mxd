# MXD Library Local Kubernetes Deployment for Windows
# This script sets up Kubernetes locally using Docker Desktop and deploys the MXD application

param(
    [Parameter(Mandatory=$true)]
    [string]$Environment = "local",
    
    [Parameter(Mandatory=$false)]
    [string]$ImageTag = "latest",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDockerCheck = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPortForward = $false
)

Write-Host "=== MXD Library Local Kubernetes Deployment (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "Image Tag: $ImageTag" -ForegroundColor Cyan
Write-Host "Port Forward: $(if ($SkipPortForward) { 'Disabled' } else { 'Enabled' })" -ForegroundColor Cyan
Write-Host "NOTE: This script requires Docker Desktop with Kubernetes enabled" -ForegroundColor Yellow
Write-Host ""

# Function to check if a command exists
function Test-Command {
    param($Command)
    $result = Get-Command $Command -ErrorAction SilentlyContinue
    if ($result) {
        return $true
    } else {
        return $false
    }
}

# Function to wait for user input
function Wait-UserInput {
    param($Message)
    Write-Host $Message -ForegroundColor Yellow
    Read-Host "Press Enter to continue or Ctrl+C to cancel"
}

# Function to start port forwarding and open browser
function Start-PortForwardAndBrowser {
    param(
        [string]$Namespace,
        [int]$LocalPort = 8081,
        [int]$RemotePort = 8080,
        [string]$DeploymentName = "mxd-enterprise-local"
    )
    
    Write-Host "Setting up port forwarding..." -ForegroundColor Blue
    
    # Check if local port is available
    $portInUse = Get-NetTCPConnection -LocalPort $LocalPort -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Host "WARNING: Port $LocalPort is already in use" -ForegroundColor Yellow
        Write-Host "You can manually access the service via NodePort: http://localhost:30080/wallet" -ForegroundColor White
        return $false
    }
    
    # Start port forwarding in background
    Write-Host "Starting kubectl port-forward in background..." -ForegroundColor Blue
    $portForwardJob = Start-Job -ScriptBlock {
        param($ns, $deployment, $localPort, $remotePort)
        kubectl port-forward "deployment/$deployment" "$localPort`:$remotePort" -n $ns
    } -ArgumentList $Namespace, $DeploymentName, $LocalPort, $RemotePort
    
    # Wait a moment for port forward to establish
    Start-Sleep -Seconds 5
    
    # Test connectivity
    $maxAttempts = 6
    $attempt = 0
    $connected = $false
    
    while ($attempt -lt $maxAttempts -and -not $connected) {
        $attempt++
        Write-Host "Testing connection (attempt $attempt/$maxAttempts)..." -ForegroundColor Gray
        
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$LocalPort/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                $connected = $true
                Write-Host "✓ Port forward established successfully" -ForegroundColor Green
            }
        } catch {
            Start-Sleep -Seconds 3
        }
    }
    
    if ($connected) {
        Write-Host "Opening wallet interface in browser..." -ForegroundColor Cyan
        Start-Process "http://localhost:$LocalPort/wallet"
        
        Write-Host ""
        Write-Host "=== Port Forward Active ===" -ForegroundColor Green
        Write-Host "Wallet Interface: http://localhost:$LocalPort/wallet" -ForegroundColor White
        Write-Host "Health Endpoint: http://localhost:$LocalPort/health" -ForegroundColor White
        Write-Host "Metrics Endpoint: http://localhost:$LocalPort/metrics" -ForegroundColor White
        Write-Host ""
        Write-Host "To stop port forwarding:" -ForegroundColor Yellow
        Write-Host "Get-Job | Where-Object {`$_.Name -like '*port*'} | Stop-Job" -ForegroundColor White
        Write-Host "Get-Job | Where-Object {`$_.Name -like '*port*'} | Remove-Job" -ForegroundColor White
        
        return $true
    } else {
        Write-Host "WARNING: Could not establish port forward connection" -ForegroundColor Yellow
        Write-Host "You can manually access the service via NodePort: http://localhost:30080/wallet" -ForegroundColor White
        
        # Clean up failed job
        Stop-Job $portForwardJob -ErrorAction SilentlyContinue
        Remove-Job $portForwardJob -ErrorAction SilentlyContinue
        
        return $false
    }
}

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Blue

if (-not $SkipDockerCheck) {
    if (-not (Test-Command "docker")) {
        Write-Host "ERROR: Docker is not installed or not in PATH" -ForegroundColor Red
        Write-Host "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        Write-Host "Make sure to enable Kubernetes in Docker Desktop settings" -ForegroundColor Yellow
        exit 1
    }

    # Check if Docker is running
    docker version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
        exit 1
    }

    # Check if Kubernetes is enabled in Docker Desktop
    kubectl version --client 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: kubectl is not available" -ForegroundColor Red
        Write-Host "Please enable Kubernetes in Docker Desktop settings:" -ForegroundColor Yellow
        Write-Host "1. Open Docker Desktop" -ForegroundColor Yellow
        Write-Host "2. Go to Settings > Kubernetes" -ForegroundColor Yellow
        Write-Host "3. Check 'Enable Kubernetes'" -ForegroundColor Yellow
        Write-Host "4. Click 'Apply & Restart'" -ForegroundColor Yellow
        exit 1
    }
}

if (-not (Test-Command "kubectl")) {
    Write-Host "ERROR: kubectl is not installed or not in PATH" -ForegroundColor Red
    Write-Host "kubectl should be installed with Docker Desktop" -ForegroundColor Yellow
    Write-Host "If not available, download from: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/" -ForegroundColor Yellow
    exit 1
}

Write-Host "Docker is available" -ForegroundColor Green
Write-Host "kubectl is available" -ForegroundColor Green

# Check Kubernetes cluster status
Write-Host "Checking Kubernetes cluster status..." -ForegroundColor Blue
$clusterInfo = kubectl cluster-info 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Kubernetes cluster is running" -ForegroundColor Green
} else {
    Write-Host "ERROR: Kubernetes cluster is not accessible" -ForegroundColor Red
    Write-Host "Please ensure Kubernetes is enabled in Docker Desktop" -ForegroundColor Yellow
    exit 1
}

# Set kubectl context to docker-desktop
Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Could not set context to docker-desktop" -ForegroundColor Yellow
    Write-Host "Current context:" -ForegroundColor Yellow
    kubectl config current-context
}

# Build Docker image locally
Write-Host "Building MXD Docker image locally..." -ForegroundColor Blue
docker build -t "mxdlib:$ImageTag" .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to build Docker image" -ForegroundColor Red
    exit 1
}

# Verify the image was built successfully
Write-Host "Verifying Docker image..." -ForegroundColor Blue
docker images mxdlib:$ImageTag
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker image not found after build" -ForegroundColor Red
    exit 1
}
Write-Host "Docker image built successfully" -ForegroundColor Green

# Create namespace
Write-Host "Creating Kubernetes namespace..." -ForegroundColor Blue
kubectl create namespace "mxd-$Environment" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Namespace mxd-$Environment created" -ForegroundColor Green
} else {
    Write-Host "Namespace mxd-$Environment already exists" -ForegroundColor Yellow
}

# Create local storage class
Write-Host "Creating local storage class..." -ForegroundColor Blue
$storageClass = "apiVersion: storage.k8s.io/v1`nkind: StorageClass`nmetadata:`n  name: local-storage`nprovisioner: docker.io/hostpath`nparameters:`n  type: Directory`nreclaimPolicy: Delete`nvolumeBindingMode: Immediate"
$storageClass | kubectl apply -f -

# Create local deployment manifest
Write-Host "Creating local deployment manifest..." -ForegroundColor Blue

# Create deployment YAML without problematic here-strings
$deploymentYaml = @()
$deploymentYaml += "apiVersion: apps/v1"
$deploymentYaml += "kind: Deployment"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-enterprise-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "  labels:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "    environment: $Environment"
$deploymentYaml += "spec:"
$deploymentYaml += "  replicas: 1"
$deploymentYaml += "  selector:"
$deploymentYaml += "    matchLabels:"
$deploymentYaml += "      app: mxd-enterprise-local"
$deploymentYaml += "  template:"
$deploymentYaml += "    metadata:"
$deploymentYaml += "      labels:"
$deploymentYaml += "        app: mxd-enterprise-local"
$deploymentYaml += "        environment: $Environment"
$deploymentYaml += "      annotations:"
$deploymentYaml += "        prometheus.io/scrape: ""true"""
$deploymentYaml += "        prometheus.io/port: ""8080"""
$deploymentYaml += "        prometheus.io/path: ""/metrics"""
$deploymentYaml += "    spec:"
$deploymentYaml += "      containers:"
$deploymentYaml += "      - name: mxd-node"
$deploymentYaml += "        image: mxdlib:$ImageTag"
$deploymentYaml += "        imagePullPolicy: IfNotPresent"
$deploymentYaml += "        ports:"
$deploymentYaml += "        - containerPort: 8000"
$deploymentYaml += "          name: p2p"
$deploymentYaml += "        - containerPort: 8080"
$deploymentYaml += "          name: metrics"
$deploymentYaml += "        env:"
$deploymentYaml += "        - name: MXD_NODE_ID"
$deploymentYaml += "          valueFrom:"
$deploymentYaml += "            fieldRef:"
$deploymentYaml += "              fieldPath: metadata.name"
$deploymentYaml += "        - name: MXD_NETWORK_MAGIC"
$deploymentYaml += "          value: ""0x4D584431"""
$deploymentYaml += "        - name: MXD_LOG_LEVEL"
$deploymentYaml += "          value: ""INFO"""
$deploymentYaml += "        - name: MXD_METRICS_PORT"
$deploymentYaml += "          value: ""8080"""
$deploymentYaml += "        - name: MXD_DATA_DIR"
$deploymentYaml += "          value: ""/opt/mxd/data"""
$deploymentYaml += "        - name: MXD_NETWORK_TYPE"
$deploymentYaml += "          value: ""testnet"""
$deploymentYaml += "        resources:"
$deploymentYaml += "          requests:"
$deploymentYaml += "            memory: ""512Mi"""
$deploymentYaml += "            cpu: ""250m"""
$deploymentYaml += "          limits:"
$deploymentYaml += "            memory: ""1Gi"""
$deploymentYaml += "            cpu: ""500m"""
$deploymentYaml += "        volumeMounts:"
$deploymentYaml += "        - name: data"
$deploymentYaml += "          mountPath: /opt/mxd/data"
$deploymentYaml += "        - name: config"
$deploymentYaml += "          mountPath: /opt/mxd/config"
$deploymentYaml += "        livenessProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 60"
$deploymentYaml += "          periodSeconds: 30"
$deploymentYaml += "        readinessProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 30"
$deploymentYaml += "          periodSeconds: 15"
$deploymentYaml += "        startupProbe:"
$deploymentYaml += "          httpGet:"
$deploymentYaml += "            path: /health"
$deploymentYaml += "            port: 8080"
$deploymentYaml += "          initialDelaySeconds: 30"
$deploymentYaml += "          periodSeconds: 10"
$deploymentYaml += "          failureThreshold: 30"
$deploymentYaml += "      volumes:"
$deploymentYaml += "      - name: data"
$deploymentYaml += "        persistentVolumeClaim:"
$deploymentYaml += "          claimName: mxd-data-local"
$deploymentYaml += "      - name: config"
$deploymentYaml += "        configMap:"
$deploymentYaml += "          name: mxd-config-local"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: Service"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-service-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "  labels:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "spec:"
$deploymentYaml += "  selector:"
$deploymentYaml += "    app: mxd-enterprise-local"
$deploymentYaml += "  ports:"
$deploymentYaml += "  - name: p2p"
$deploymentYaml += "    port: 8000"
$deploymentYaml += "    targetPort: 8000"
$deploymentYaml += "    nodePort: 30000"
$deploymentYaml += "  - name: metrics"
$deploymentYaml += "    port: 8080"
$deploymentYaml += "    targetPort: 8080"
$deploymentYaml += "    nodePort: 30080"
$deploymentYaml += "  type: NodePort"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: PersistentVolumeClaim"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-data-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "spec:"
$deploymentYaml += "  accessModes:"
$deploymentYaml += "    - ReadWriteOnce"
$deploymentYaml += "  resources:"
$deploymentYaml += "    requests:"
$deploymentYaml += "      storage: 20Gi"
$deploymentYaml += "  storageClassName: hostpath"
$deploymentYaml += "---"
$deploymentYaml += "apiVersion: v1"
$deploymentYaml += "kind: ConfigMap"
$deploymentYaml += "metadata:"
$deploymentYaml += "  name: mxd-config-local"
$deploymentYaml += "  namespace: mxd-$Environment"
$deploymentYaml += "data:"

# Create JSON config using simple string concatenation to avoid parsing issues
$jsonConfigContent = "  local.json: |"
$jsonConfigContent += "`n    {"
$jsonConfigContent += "`n      ""port"": 8000,"
$jsonConfigContent += "`n      ""data_dir"": ""/opt/mxd/data"","
$jsonConfigContent += "`n      ""network_type"": ""testnet"","
$jsonConfigContent += "`n      ""metrics_port"": 8080,"
$jsonConfigContent += "`n      ""log_level"": ""INFO"""
$jsonConfigContent += "`n    }"

$deploymentYaml += $jsonConfigContent

$deploymentManifest = $deploymentYaml -join "`n"

# Apply the deployment
Write-Host "Applying Kubernetes manifests..." -ForegroundColor Blue
$deploymentManifest | kubectl apply -f -
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to apply Kubernetes manifests" -ForegroundColor Red
    exit 1
}

Write-Host "Kubernetes manifests applied successfully" -ForegroundColor Green

# Wait for deployment to be ready
Write-Host "Waiting for deployment to be ready..." -ForegroundColor Blue
kubectl wait --for=condition=available --timeout=300s deployment/mxd-enterprise-local -n "mxd-$Environment"
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Deployment did not become ready within 5 minutes" -ForegroundColor Yellow
    Write-Host "Check pod status with: kubectl get pods -n mxd-$Environment" -ForegroundColor Yellow
    Write-Host "Check pod logs with: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor Yellow
} else {
    Write-Host "Deployment is ready" -ForegroundColor Green
}

# Get service information
Write-Host "Getting service information..." -ForegroundColor Blue
kubectl get services -n "mxd-$Environment"

# Get pod information
Write-Host "Getting pod information..." -ForegroundColor Blue
kubectl get pods -n "mxd-$Environment"

Write-Host ""
Write-Host "=== Local Deployment Complete ===" -ForegroundColor Green

# Set up port forwarding if not skipped
if (-not $SkipPortForward) {
    $portForwardSuccess = Start-PortForwardAndBrowser -Namespace "mxd-$Environment" -LocalPort 8081 -RemotePort 8080 -DeploymentName "mxd-enterprise-local"
    
    if (-not $portForwardSuccess) {
        Write-Host ""
        Write-Host "Port forwarding failed, using NodePort access:" -ForegroundColor Yellow
    }
} else {
    Write-Host "Port forwarding skipped. Access via NodePort:" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Access your MXD node:" -ForegroundColor Cyan
if (-not $SkipPortForward) {
    Write-Host "Preferred (Port Forward):" -ForegroundColor Green
    Write-Host "  Wallet Interface: http://localhost:8081/wallet" -ForegroundColor White
    Write-Host "  Health endpoint: http://localhost:8081/health" -ForegroundColor White
    Write-Host "  Metrics endpoint: http://localhost:8081/metrics" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternative (NodePort):" -ForegroundColor Yellow
}
Write-Host "  Health endpoint: http://localhost:30080/health" -ForegroundColor White
Write-Host "  Metrics endpoint: http://localhost:30080/metrics" -ForegroundColor White
Write-Host "  Wallet endpoint: http://localhost:30080/wallet" -ForegroundColor White
Write-Host "  P2P port: localhost:30000" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "Check pod status: kubectl get pods -n mxd-$Environment" -ForegroundColor White
Write-Host "View logs: kubectl logs -f deployment/mxd-enterprise-local -n mxd-$Environment" -ForegroundColor White
Write-Host "Scale deployment: kubectl scale deployment mxd-enterprise-local --replicas=2 -n mxd-$Environment" -ForegroundColor White
Write-Host "Delete deployment: kubectl delete namespace mxd-$Environment" -ForegroundColor White
if (-not $SkipPortForward) {
    Write-Host "Stop port forwarding: Get-Job | Where-Object {`$_.Name -like '*port*'} | Stop-Job; Get-Job | Remove-Job" -ForegroundColor White
}
Write-Host ""
Write-Host "Local deployment completed successfully!" -ForegroundColor Green
