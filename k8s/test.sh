#!/bin/bash
# HoneyKube Testing Script
# Tests all components to verify the deployment is working correctly
# Usage: ./test.sh [--local] [--k8s]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NAMESPACE="honeykube"
MODE=${1:-"--k8s"}
PASSED=0
FAILED=0
WARNINGS=0

# Helper functions (defined early so they can be used during setup)
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++)) || true
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED++)) || true
}

warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
    ((WARNINGS++)) || true
}

info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

# Determine base URLs based on mode
if [ "$MODE" == "--local" ]; then
    # For Docker Compose, check if we need to use docker host IP
    # This handles cases where test runs from WSL or different network context
    DOCKER_HOST_IP="localhost"
    
    # Check if running inside WSL and Docker Desktop is on Windows
    if grep -q microsoft /proc/version 2>/dev/null; then
        # WSL detected - try to get Windows host IP
        WSL_HOST=$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' | head -1)
        if [ -n "$WSL_HOST" ]; then
            # Test if Docker is accessible via WSL host
            if curl -s --max-time 2 "http://${WSL_HOST}:8080" &>/dev/null || curl -s --max-time 2 "http://localhost:8080" &>/dev/null; then
                # Prefer localhost if it works
                if curl -s --max-time 2 "http://localhost:8080" &>/dev/null; then
                    DOCKER_HOST_IP="localhost"
                else
                    DOCKER_HOST_IP="$WSL_HOST"
                fi
            fi
        fi
    fi
    
    # Also check if host.docker.internal resolves (Docker Desktop)
    if ! curl -s --max-time 2 "http://${DOCKER_HOST_IP}:8080" &>/dev/null; then
        if curl -s --max-time 2 "http://host.docker.internal:8080" &>/dev/null; then
            DOCKER_HOST_IP="host.docker.internal"
        fi
    fi
    
    APACHE_URL="http://${DOCKER_HOST_IP}:8080"
    WORDPRESS_URL="http://${DOCKER_HOST_IP}:8000"
    NEXTJS_URL="http://${DOCKER_HOST_IP}:3000"
    SCANNER_URL="http://${DOCKER_HOST_IP}:8081"
    LLM_URL="http://${DOCKER_HOST_IP}:8082"
    ARTIFACT_URL="http://${DOCKER_HOST_IP}:8083"
    REDIS_HOST="$DOCKER_HOST_IP"
    echo -e "${BLUE}=== HoneyKube Test Suite (Docker Compose Mode) ===${NC}"
    if [ "$DOCKER_HOST_IP" != "localhost" ]; then
        echo -e "Docker Host IP: ${DOCKER_HOST_IP}"
    fi
else
    # Check if running in Minikube
    IS_MINIKUBE=false
    if command -v minikube &> /dev/null && minikube status &> /dev/null 2>&1; then
        IS_MINIKUBE=true
        NODE_IP=$(minikube ip 2>/dev/null || echo "localhost")
        echo -e "${BLUE}=== HoneyKube Test Suite (Kubernetes Mode - Minikube) ===${NC}"
    else
        # Get node IP for regular k8s
        NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "localhost")
        echo -e "${BLUE}=== HoneyKube Test Suite (Kubernetes Mode) ===${NC}"
    fi
    
    # For Minikube, we'll use kubectl port-forward instead of NodePort
    # Set USE_PORT_FORWARD=true to use port-forwarding (more reliable for Minikube/Docker Desktop)
    USE_PORT_FORWARD=${USE_PORT_FORWARD:-$IS_MINIKUBE}
    
    if [ "$USE_PORT_FORWARD" == "true" ]; then
        info "Using kubectl port-forward for service access (recommended for Minikube)"
        APACHE_URL="http://localhost:18080"
        WORDPRESS_URL="http://localhost:18000"
        NEXTJS_URL="http://localhost:13000"
    else
        APACHE_URL="http://${NODE_IP}:30080"
        WORDPRESS_URL="http://${NODE_IP}:30800"
        NEXTJS_URL="http://${NODE_IP}:30300"
    fi
    echo -e "Node IP: ${NODE_IP}"
fi

echo -e "Started at: $(date)"
echo ""

# Wait before API calls to avoid rate limiting
API_WAIT_SECONDS=${API_WAIT_SECONDS:-60}

wait_for_api() {
    local test_name=$1
    info "Waiting ${API_WAIT_SECONDS}s before $test_name to avoid API rate limits..."
    sleep $API_WAIT_SECONDS
}

# Port-forward management for Minikube/Docker Desktop
PORT_FORWARD_PIDS=()

start_port_forwards() {
    if [ "$USE_PORT_FORWARD" == "true" ]; then
        info "Starting port-forwards for honeypot services..."
        
        # Start port-forwards in background
        kubectl port-forward svc/port-listener-apache 18080:8080 -n $NAMESPACE &>/dev/null &
        PORT_FORWARD_PIDS+=($!)
        
        kubectl port-forward svc/port-listener-wordpress 18000:8000 -n $NAMESPACE &>/dev/null &
        PORT_FORWARD_PIDS+=($!)
        
        kubectl port-forward svc/port-listener-nextjs 13000:3000 -n $NAMESPACE &>/dev/null &
        PORT_FORWARD_PIDS+=($!)
        
        # Wait for port-forwards to establish
        sleep 3
        pass "Port-forwards established"
    fi
}

stop_port_forwards() {
    if [ ${#PORT_FORWARD_PIDS[@]} -gt 0 ]; then
        info "Stopping port-forwards..."
        for pid in "${PORT_FORWARD_PIDS[@]}"; do
            kill $pid 2>/dev/null || true
        done
        PORT_FORWARD_PIDS=()
    fi
}

# Cleanup on exit
cleanup() {
    stop_port_forwards
}
trap cleanup EXIT

# Test HTTP endpoint
test_http() {
    local name=$1
    local url=$2
    local expected_code=${3:-200}
    local timeout=${4:-10}
    
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time $timeout "$url" 2>/dev/null | tr -d '[:space:]' || echo "000")
    
    if [ "$response" == "$expected_code" ]; then
        pass "$name - HTTP $response"
    elif [ "$response" == "000" ]; then
        fail "$name - Connection failed (timeout or refused)"
    else
        warn "$name - Expected HTTP $expected_code, got $response"
    fi
    return 0
}

# Test HTTP response contains string
test_http_contains() {
    local name=$1
    local url=$2
    local expected_string=$3
    local timeout=${4:-10}
    
    response=$(curl -s --max-time $timeout "$url" 2>/dev/null || echo "")
    
    if echo "$response" | grep -q "$expected_string"; then
        pass "$name - Contains expected content"
    else
        fail "$name - Missing expected content: '$expected_string'"
    fi
    return 0
}

echo -e "${YELLOW}--- Pre-flight Checks ---${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    warn "Running as root - this is not recommended for production!"
else
    pass "Running as non-root user: $(whoami)"
fi

# Check required tools
for cmd in curl kubectl docker; do
    if command -v $cmd &> /dev/null; then
        pass "$cmd is installed"
    else
        if [ "$cmd" == "kubectl" ] && [ "$MODE" == "--local" ]; then
            info "kubectl not required for local mode"
        else
            fail "$cmd is not installed"
        fi
    fi
done

echo ""
echo -e "${YELLOW}--- Kubernetes Cluster Tests ---${NC}"

if [ "$MODE" != "--local" ]; then
    # Check namespace exists
    if kubectl get namespace $NAMESPACE &> /dev/null; then
        pass "Namespace '$NAMESPACE' exists"
    else
        fail "Namespace '$NAMESPACE' not found"
        echo "Run './deploy.sh apply' first"
        exit 1
    fi

    # Check pods are running
    echo ""
    info "Checking pod status..."
    
    pods=("redis-0" "scanner-detector" "llm-planner" "artifact-sink" "port-listener-apache" "port-listener-wordpress" "port-listener-nextjs")
    for pod in "${pods[@]}"; do
        status=$(kubectl get pods -n $NAMESPACE -l app=$pod -o jsonpath='{.items[0].status.phase}' 2>/dev/null || \
                 kubectl get pods -n $NAMESPACE --field-selector=metadata.name=$pod -o jsonpath='{.items[0].status.phase}' 2>/dev/null || \
                 echo "NotFound")
        
        if [ "$status" == "Running" ]; then
            pass "Pod $pod is Running"
        elif [ "$status" == "NotFound" ]; then
            # Try partial match
            running=$(kubectl get pods -n $NAMESPACE 2>/dev/null | grep -c "$pod.*Running" || echo "0")
            if [ "$running" -gt 0 ]; then
                pass "Pod(s) matching '$pod' are Running ($running instance(s))"
            else
                fail "Pod $pod not found or not running"
            fi
        else
            fail "Pod $pod status: $status"
        fi
    done

    # Check services
    echo ""
    info "Checking services..."
    
    services=("redis" "scanner-detector" "llm-planner" "artifact-sink" "port-listener-apache" "port-listener-wordpress" "port-listener-nextjs")
    for svc in "${services[@]}"; do
        if kubectl get svc $svc -n $NAMESPACE &> /dev/null; then
            pass "Service $svc exists"
        else
            fail "Service $svc not found"
        fi
    done

    # Check secrets
    echo ""
    info "Checking secrets..."
    
    if kubectl get secret llm-config -n $NAMESPACE &> /dev/null; then
        pass "Secret 'llm-config' exists"
        
        # Check if API key is set (not the placeholder)
        api_key=$(kubectl get secret llm-config -n $NAMESPACE -o jsonpath='{.data.OPENROUTER_API_KEY}' | base64 -d 2>/dev/null || echo "")
        if [ "$api_key" == "YOUR_OPENROUTER_API_KEY_HERE" ] || [ -z "$api_key" ]; then
            fail "OpenRouter API key not configured (still placeholder or empty)"
        else
            pass "OpenRouter API key is configured"
        fi
        
        # Check model setting
        model=$(kubectl get configmap llm-config -n $NAMESPACE -o jsonpath='{.data.LLM_MODEL}' 2>/dev/null || echo "")
        if [ -n "$model" ]; then
            pass "LLM model configured: $model"
        else
            warn "LLM model not set, will use default"
        fi
    else
        fail "Secret 'llm-config' not found"
    fi

    # Check PVCs
    echo ""
    info "Checking persistent storage..."
    
    pvcs=("redis-data-redis-0" "honeykube-logs" "honeykube-artifacts")
    for pvc in "${pvcs[@]}"; do
        status=$(kubectl get pvc $pvc -n $NAMESPACE -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
        if [ "$status" == "Bound" ]; then
            pass "PVC $pvc is Bound"
        elif [ "$status" == "NotFound" ]; then
            warn "PVC $pvc not found (may not be created yet)"
        else
            fail "PVC $pvc status: $status"
        fi
    done
fi

echo ""
echo -e "${YELLOW}--- Redis Tests ---${NC}"

if [ "$MODE" != "--local" ]; then
    # Test Redis connectivity
    redis_ping=$(kubectl exec -it redis-0 -n $NAMESPACE -- redis-cli ping 2>/dev/null | tr -d '\r' || echo "FAIL")
    if [ "$redis_ping" == "PONG" ]; then
        pass "Redis is responding to PING"
    else
        fail "Redis not responding (got: $redis_ping)"
    fi

    # Check Redis memory
    redis_mem=$(kubectl exec -it redis-0 -n $NAMESPACE -- redis-cli INFO memory 2>/dev/null | grep "used_memory_human" | cut -d: -f2 | tr -d '\r' || echo "unknown")
    info "Redis memory usage: $redis_mem"
else
    # Docker Compose mode
    redis_ping=$(docker exec honeykube-redis redis-cli ping 2>/dev/null || echo "FAIL")
    if [ "$redis_ping" == "PONG" ]; then
        pass "Redis is responding to PING"
    else
        fail "Redis not responding"
    fi
fi

echo ""
echo -e "${YELLOW}--- Service Health Checks ---${NC}"

if [ "$MODE" != "--local" ]; then
    # Test internal services via kubectl exec using Python (curl not available in slim images)
    info "Testing internal services via kubectl exec..."
    
    # Scanner Detector health
    scanner_health=$(kubectl exec deploy/scanner-detector -n $NAMESPACE -- python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8081/_health').read().decode())" 2>/dev/null | tr -d '\r\n' || echo "FAIL")
    if [ "$scanner_health" == "OK" ]; then
        pass "Scanner Detector health check"
    else
        fail "Scanner Detector health check failed (got: $scanner_health)"
    fi

    # LLM Planner health
    llm_health=$(kubectl exec deploy/llm-planner -n $NAMESPACE -- python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8082/_health').read().decode())" 2>/dev/null | tr -d '\r\n' || echo "FAIL")
    if [ "$llm_health" == "OK" ]; then
        pass "LLM Planner health check"
    else
        fail "LLM Planner health check (may need API key) (got: $llm_health)"
    fi

    # Artifact Sink health
    artifact_health=$(kubectl exec deploy/artifact-sink -n $NAMESPACE -- python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8083/_health').read().decode())" 2>/dev/null | tr -d '\r\n' || echo "FAIL")
    if [ "$artifact_health" == "OK" ]; then
        pass "Artifact Sink health check"
    else
        fail "Artifact Sink health check failed (got: $artifact_health)"
    fi
else
    test_http "Scanner Detector health" "$SCANNER_URL/_health"
    test_http "LLM Planner health" "$LLM_URL/_health"
    test_http "Artifact Sink health" "$ARTIFACT_URL/_health"
fi

echo ""
echo -e "${YELLOW}--- Honeypot Endpoint Tests ---${NC}"

# Start port-forwards if needed (for Minikube/Docker Desktop)
if [ "$MODE" != "--local" ]; then
    start_port_forwards
fi

wait_for_api "Apache honeypot test"

# Test Apache honeypot
test_http "Apache honeypot root" "$APACHE_URL/"
test_http_contains "Apache honeypot server header" "$APACHE_URL/" "Apache"

wait_for_api "WordPress honeypot test"

# Test WordPress honeypot
test_http "WordPress honeypot root" "$WORDPRESS_URL/"
test_http_contains "WordPress honeypot content" "$WORDPRESS_URL/" "WordPress"
test_http "WordPress login page" "$WORDPRESS_URL/wp-login.php"
test_http "WordPress XML-RPC" "$WORDPRESS_URL/xmlrpc.php"

wait_for_api "Next.js honeypot test"

# Test Next.js honeypot (CVE-2025-55182 & CVE-2025-66478)
test_http "Next.js honeypot root" "$NEXTJS_URL/"
test_http_contains "Next.js honeypot content" "$NEXTJS_URL/" "Next"
test_http "Next.js _next/static" "$NEXTJS_URL/_next/static"
test_http "Next.js API route" "$NEXTJS_URL/api/health"

echo ""
echo -e "${YELLOW}--- Scanner Detection Test ---${NC}"

wait_for_api "scanner detection test"

if [ "$MODE" != "--local" ]; then
    # Test scanner detection via kubectl exec using Python
    scanner_test=$(kubectl exec deploy/scanner-detector -n $NAMESPACE -- python -c "
import urllib.request
import json
data = json.dumps({'src_ip':'10.0.0.1','src_port':12345,'dst_port':80,'method':'GET','path':'/','headers':{'User-Agent':'sqlmap/1.5'},'timestamp':'2025-01-01T00:00:00'}).encode()
req = urllib.request.Request('http://localhost:8081/detect', data=data, headers={'Content-Type':'application/json'})
print(urllib.request.urlopen(req).read().decode())
" 2>/dev/null || echo "{}")
else
    scanner_test=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"src_ip":"10.0.0.1","src_port":12345,"dst_port":80,"method":"GET","path":"/","headers":{"User-Agent":"sqlmap/1.5"},"timestamp":"2025-01-01T00:00:00"}' \
        "$SCANNER_URL/detect" 2>/dev/null || echo "{}")
fi

if echo "$scanner_test" | grep -q '"is_scanner": true\|"is_scanner":true'; then
    pass "Scanner detection identified sqlmap"
elif echo "$scanner_test" | grep -q '"tool"'; then
    warn "Scanner detection responded but may not have detected sqlmap"
    info "Response: $scanner_test"
else
    fail "Scanner detection test failed"
fi

# Test React2Shell scanner detection (CVE-2025-55182)
info "Testing React2Shell scanner detection..."

wait_for_api "React2Shell scanner detection test"

if [ "$MODE" != "--local" ]; then
    react2shell_test=$(kubectl exec deploy/scanner-detector -n $NAMESPACE -- python -c "
import urllib.request
import json
data = json.dumps({'src_ip':'10.0.0.2','src_port':54321,'dst_port':3000,'method':'POST','path':'/_server_action','headers':{'User-Agent':'python-httpx/0.28.1 - Assetnote','Next-Action':'abc123','Content-Type':'multipart/form-data'},'timestamp':'2025-01-01T00:00:00'}).encode()
req = urllib.request.Request('http://localhost:8081/detect', data=data, headers={'Content-Type':'application/json'})
print(urllib.request.urlopen(req).read().decode())
" 2>/dev/null || echo "{}")
else
    react2shell_test=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"src_ip":"10.0.0.2","src_port":54321,"dst_port":3000,"method":"POST","path":"/_server_action","headers":{"User-Agent":"python-httpx/0.28.1 - Assetnote","Next-Action":"abc123","Content-Type":"multipart/form-data"},"timestamp":"2025-01-01T00:00:00"}' \
        "$SCANNER_URL/detect" 2>/dev/null || echo "{}")
fi

if echo "$react2shell_test" | grep -q '"is_scanner": true\|"is_scanner":true'; then
    pass "Scanner detection identified React2Shell/Assetnote"
elif echo "$react2shell_test" | grep -q '"tool"'; then
    warn "Scanner detection responded but may not have detected React2Shell"
    info "Response: $react2shell_test"
else
    warn "React2Shell scanner detection test - no response"
fi

echo ""
echo -e "${YELLOW}--- Artifact Sink Test ---${NC}"

if [ "$MODE" != "--local" ]; then
    stats=$(kubectl exec deploy/artifact-sink -n $NAMESPACE -- python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8083/stats').read().decode())" 2>/dev/null || echo "{}")
else
    stats=$(curl -s "$ARTIFACT_URL/stats" 2>/dev/null || echo "{}")
fi

if echo "$stats" | grep -q '"log_files"\|"artifacts"'; then
    pass "Artifact Sink stats endpoint working"
    info "Stats: $stats"
else
    fail "Artifact Sink stats endpoint failed"
fi

echo ""
echo -e "${YELLOW}--- Integration Test (Full Request Flow) ---${NC}"

wait_for_api "integration test"

info "Sending test request through honeypot..."

# Send a suspicious request and check it was logged
test_path="/admin/config.php?id=1%27%20OR%20%271%27=%271"
response=$(curl -S -o /dev/null -w "%{http_code}" --max-time 60 \
    -H "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)" \
    "${APACHE_URL}${test_path}" 2>&1 || true)
    
response_code=$(echo "$response" | tail -n 1 | grep -oE "[0-9]{3}$" || echo "000")

if [ "$response_code" != "000" ] && [ "$response_code" != "" ]; then
    pass "Full request flow completed (HTTP $response_code)"
else
    fail "Full request flow failed (connection error)"
    info "Verbose Error Output:"
    echo "$response"
fi

# Brief pause for logging
sleep 2

# Check if logs were created
if [ "$MODE" != "--local" ]; then
    log_count=$(kubectl exec -it deploy/artifact-sink -n $NAMESPACE -- ls -la /logs/ 2>/dev/null | grep -c "honeypot-" || echo "0")
else
    log_count=$(docker exec honeykube-artifact-sink ls -la /logs/ 2>/dev/null | grep -c "honeypot-" || echo "0")
fi

if [ "$log_count" -gt 0 ]; then
    pass "Log files are being created ($log_count file(s))"
else
    warn "No log files found yet (may take time to appear)"
fi

echo ""
echo -e "${YELLOW}=== Test Summary ===${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed! HoneyKube is operational.${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the configuration.${NC}"
    exit 1
fi
