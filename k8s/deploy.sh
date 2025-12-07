#!/bin/bash
# HoneyKube Kubernetes Deployment Script
# Usage: ./deploy.sh [apply|delete|build]

set -e

NAMESPACE="honeykube"
ACTION=${1:-apply}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="${SCRIPT_DIR}"
PROJECT_DIR="$(dirname "${K8S_DIR}")"

echo "=== HoneyKube Deployment Script ==="
echo "Action: ${ACTION}"
echo "Namespace: ${NAMESPACE}"
echo ""

# Function to wait for pods to be ready
wait_for_pods() {
    local label=$1
    local timeout=${2:-120}
    echo "Waiting for pods with label ${label} to be ready..."
    kubectl wait --for=condition=ready pod -l "${label}" -n "${NAMESPACE}" --timeout="${timeout}s" || true
}

# Function to build Docker images
build_images() {
    echo "=== Building Docker Images ==="
    cd "${PROJECT_DIR}"
    
    # Detect Kubernetes environment
    K8S_ENV="unknown"
    if command -v minikube &> /dev/null && minikube status &> /dev/null; then
        K8S_ENV="minikube"
        echo "Detected minikube - configuring Docker environment..."
        eval $(minikube docker-env)
    elif command -v kind &> /dev/null && kind get clusters &> /dev/null 2>&1; then
        K8S_ENV="kind"
        echo "Detected kind cluster..."
    fi
    
    echo "Building scanner-detector image..."
    docker build -t honeykube/scanner-detector:latest -f services/scanner-detector/Dockerfile .
    
    echo "Building llm-planner image..."
    docker build -t honeykube/llm-planner:latest -f services/llm-planner/Dockerfile .
    
    echo "Building artifact-sink image..."
    docker build -t honeykube/artifact-sink:latest -f services/artifact-sink/Dockerfile .
    
    echo "Building port-listener image..."
    docker build -t honeykube/port-listener:latest -f services/port-listener/Dockerfile .
    
    # Load images into kind if needed
    if [ "$K8S_ENV" == "kind" ]; then
        CLUSTER_NAME=$(kind get clusters | head -1)
        echo "Loading images into kind cluster: ${CLUSTER_NAME}..."
        kind load docker-image honeykube/scanner-detector:latest --name "${CLUSTER_NAME}"
        kind load docker-image honeykube/llm-planner:latest --name "${CLUSTER_NAME}"
        kind load docker-image honeykube/artifact-sink:latest --name "${CLUSTER_NAME}"
        kind load docker-image honeykube/port-listener:latest --name "${CLUSTER_NAME}"
    fi
    
    echo ""
    echo "=== Docker Images Built Successfully ==="
    docker images | grep honeykube
    echo ""
}

if [ "${ACTION}" == "build" ]; then
    build_images
    exit 0
fi

if [ "${ACTION}" == "apply" ]; then
    echo "=== Creating HoneyKube resources ==="
    
    # Check if images exist, if not build them
    if ! docker images | grep -q "honeykube/scanner-detector"; then
        echo "Docker images not found. Building images first..."
        build_images
    else
        echo "Docker images found. Skipping build (use './deploy.sh build' to rebuild)"
    fi
    
    # Create namespace first
    echo "Creating namespace..."
    kubectl apply -f "${K8S_DIR}/namespace.yaml" --validate=false
    
    # Create secrets (reminder to update)
    echo ""
    echo "⚠️  IMPORTANT: Update the OpenRouter API key in secrets.yaml before proceeding!"
    echo "   Edit k8s/secrets.yaml and replace YOUR_OPENROUTER_API_KEY_HERE"
    echo ""
    read -p "Press Enter to continue after updating the secret..."
    
    # Apply ConfigMaps and Secrets
    echo "Creating ConfigMaps and Secrets..."
    kubectl apply -f "${K8S_DIR}/configmaps.yaml" --validate=false
    kubectl apply -f "${K8S_DIR}/secrets.yaml" --validate=false
    
    # Deploy Redis first
    echo "Deploying Redis..."
    kubectl apply -f "${K8S_DIR}/redis.yaml" --validate=false
    wait_for_pods "app=redis"
    
    # Deploy backend services
    echo "Deploying Scanner Detector..."
    kubectl apply -f "${K8S_DIR}/scanner-detector.yaml" --validate=false
    
    echo "Deploying LLM Planner..."
    kubectl apply -f "${K8S_DIR}/llm-planner.yaml" --validate=false
    
    echo "Deploying Artifact Sink..."
    kubectl apply -f "${K8S_DIR}/artifact-sink.yaml" --validate=false
    
    # Wait for backend services
    wait_for_pods "app=scanner-detector"
    wait_for_pods "app=llm-planner" 180
    wait_for_pods "app=artifact-sink"
    
    # Deploy port listeners
    echo "Deploying Port Listeners..."
    kubectl apply -f "${K8S_DIR}/port-listeners.yaml" --validate=false
    wait_for_pods "app.kubernetes.io/component=port-listener"
    
    # Apply HPA and Network Policies
    echo "Applying HPA and Network Policies..."
    kubectl apply -f "${K8S_DIR}/hpa-network.yaml" --validate=false
    
    echo ""
    echo "=== Deployment Complete ==="
    echo ""
    echo "Services exposed:"
    kubectl get svc -n "${NAMESPACE}" -o wide
    echo ""
    echo "Pods status:"
    kubectl get pods -n "${NAMESPACE}"
    echo ""
    echo "Access the honeypots at:"
    echo "  - Apache (port 30080): http://<node-ip>:30080"
    echo "  - WordPress (port 30800): http://<node-ip>:30800"
    echo "  - Next.js (port 30300): http://<node-ip>:30300  [CVE-2025-55182/CVE-2025-66478]"
    
elif [ "${ACTION}" == "delete" ]; then
    echo "=== Deleting HoneyKube resources ==="
    
    kubectl delete -f "${K8S_DIR}/hpa-network.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/port-listeners.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/artifact-sink.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/llm-planner.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/scanner-detector.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/redis.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/secrets.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/configmaps.yaml" --ignore-not-found
    kubectl delete -f "${K8S_DIR}/namespace.yaml" --ignore-not-found
    
    echo "=== Deletion Complete ==="
    
else
    echo "Usage: $0 [apply|delete|build]"
    echo ""
    echo "Commands:"
    echo "  apply  - Build images (if needed) and deploy to Kubernetes"
    echo "  delete - Remove all HoneyKube resources from Kubernetes"
    echo "  build  - Build Docker images only (without deploying)"
    exit 1
fi
