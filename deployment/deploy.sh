#!/bin/bash
set -e

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

kubectl apply -f "$DEPLOY_DIR/namespace.yaml"
kubectl apply -f "$DEPLOY_DIR/serviceaccount.yaml"
kubectl apply -f "$DEPLOY_DIR/configmap.yaml"
kubectl apply -f "$DEPLOY_DIR/secret.yaml"
kubectl apply -f "$DEPLOY_DIR/deployment.yaml"
kubectl apply -f "$DEPLOY_DIR/service.yaml"

echo "Done. Checking pod status..."
kubectl rollout status deployment/agent-test -n test-agents
