# MXD Library Local Kubernetes Clean Script for Windows
# This script completely removes the local MXD deployment and all associated resources

param(
    [Parameter(Mandatory=$false)]
    [string]$Environment = "local",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

Write-Host "=== MXD Library Local Kubernetes Clean Script (Windows) ===" -ForegroundColor Green
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This will permanently delete all local MXD resources!" -ForegroundColor Red

if (-not $Force) {
    $confirmation = Read-Host "Are you sure you want to continue? Type 'yes' to confirm"
    if ($confirmation -ne "yes") {
        Write-Host "Operation cancelled" -ForegroundColor Yellow
        exit 0
    }
}

# Check if kubectl is available
if (-not (Get-Command "kubectl" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: kubectl is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Set kubectl context to docker-desktop
Write-Host "Setting kubectl context to docker-desktop..." -ForegroundColor Blue
kubectl config use-context docker-desktop

# Delete namespace (this removes all resources within it)
Write-Host "Deleting Kubernetes namespace and all resources..." -ForegroundColor Blue
kubectl delete namespace "mxd-$Environment" --ignore-not-found=true
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Namespace mxd-$Environment deleted" -ForegroundColor Green
} else {
    Write-Host "WARNING: Namespace may not exist or already deleted" -ForegroundColor Yellow
}

# Clean up storage class
Write-Host "Cleaning up storage class..." -ForegroundColor Blue
kubectl delete storageclass local-storage --ignore-not-found=true 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Storage class deleted" -ForegroundColor Green
} else {
    Write-Host "✓ Storage class not found or already deleted" -ForegroundColor Yellow
}

# Optional: Remove Docker images
Write-Host ""
$removeImages = Read-Host "Remove local Docker images? (y/N)"
if ($removeImages -eq "y" -or $removeImages -eq "Y") {
    Write-Host "Removing local Docker images..." -ForegroundColor Blue
    
    # Remove MXD images
    docker rmi mxdlib:latest 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Removed mxdlib:latest image" -ForegroundColor Green
    } else {
        Write-Host "✓ mxdlib:latest image not found" -ForegroundColor Yellow
    }
    
    # Remove dangling images
    $danglingImages = docker images -f "dangling=true" -q
    if ($danglingImages) {
        docker rmi $danglingImages 2>$null
        Write-Host "✓ Removed dangling images" -ForegroundColor Green
    } else {
        Write-Host "✓ No dangling images found" -ForegroundColor Yellow
    }
} else {
    Write-Host "Skipping Docker image cleanup" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Local Clean Complete ===" -ForegroundColor Green
Write-Host "All MXD local deployment resources have been deleted:" -ForegroundColor White
Write-Host "  ✓ Kubernetes namespace (mxd-$Environment)" -ForegroundColor Green
Write-Host "  ✓ All deployments, services, and pods" -ForegroundColor Green
Write-Host "  ✓ Persistent volume claims and data" -ForegroundColor Green
Write-Host "  ✓ ConfigMaps and secrets" -ForegroundColor Green
Write-Host "  ✓ Storage classes" -ForegroundColor Green
if ($removeImages -eq "y" -or $removeImages -eq "Y") {
    Write-Host "  ✓ Docker images" -ForegroundColor Green
}
Write-Host ""
Write-Host "Your local Kubernetes cluster is now clean of MXD deployment resources." -ForegroundColor White
Write-Host "Docker Desktop and Kubernetes remain running and available for new deployments." -ForegroundColor White
