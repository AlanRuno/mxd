# MXD Library Local Kubernetes Stop Script for Windows
# This script stops the local MXD deployment on Kubernetes

param(
    [Parameter(Mandatory=$false)]
    [string]$Environment = "local"
)

Write-Host "=== MXD Library Local Kubernetes Stop Script (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host ""

# Check if kubectl is available
if (-not (Get-Command "kubectl" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: kubectl is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Set kubectl context to docker-desktop
Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop

# Check if namespace exists
$namespaceExists = kubectl get namespace "mxd-$Environment" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Namespace mxd-$Environment does not exist or is already deleted" -ForegroundColor Yellow
    exit 0
}

Write-Host "Stopping MXD local application deployment..." -ForegroundColor Blue
kubectl scale deployment mxd-enterprise-local --replicas=0 -n "mxd-$Environment" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Deployment scaled down to 0 replicas" -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not scale down deployment (may not exist)" -ForegroundColor Yellow
}

Write-Host "Deleting application pods..." -ForegroundColor Blue
kubectl delete pods --all -n "mxd-$Environment" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ All pods deleted" -ForegroundColor Green
} else {
    Write-Host "WARNING: No pods found or already deleted" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Local Stop Complete ===" -ForegroundColor Green
Write-Host "All deployments have been scaled down to 0 replicas and pods deleted." -ForegroundColor White
Write-Host "The namespace and persistent resources remain available." -ForegroundColor White
Write-Host ""
Write-Host "To restart the deployment:" -ForegroundColor Cyan
Write-Host "kubectl scale deployment mxd-enterprise-local --replicas=1 -n mxd-$Environment" -ForegroundColor White
Write-Host ""
Write-Host "To completely remove all resources:" -ForegroundColor Cyan
Write-Host "kubectl delete namespace mxd-$Environment" -ForegroundColor White
Write-Host ""
Write-Host "Or use the clean script:" -ForegroundColor Cyan
Write-Host ".\scripts\clean-local-windows.ps1 -Environment $Environment" -ForegroundColor White
