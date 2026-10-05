#!/usr/bin/env bash
# Remove everything deploy_demo.sh created (function, role, implicit log
# group) -- and nothing else. Hard rule: this script only ever deletes
# resources named airsaws-decorator-demo*.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
FN="airsaws-decorator-demo"
ROLE="airsaws-decorator-demo-role"

case "$FN" in airsaws-*) ;; *) echo "refusing: $FN is not airsaws-*"; exit 1;; esac
case "$ROLE" in airsaws-*) ;; *) echo "refusing: $ROLE is not airsaws-*"; exit 1;; esac

echo "==> deleting Lambda $FN"
if aws lambda get-function --function-name "$FN" --region "$REGION" >/dev/null 2>&1; then
  aws lambda delete-function --function-name "$FN" --region "$REGION"
else
  echo "    (already gone)"
fi

echo "==> deleting log group /aws/lambda/$FN"
if aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/$FN" --region "$REGION" \
     --query 'logGroups[?logGroupName==`/aws/lambda/'"$FN"'`]' --output text | grep -q .; then
  aws logs delete-log-group --log-group-name "/aws/lambda/$FN" --region "$REGION"
else
  echo "    (already gone)"
fi

echo "==> deleting role $ROLE"
if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam detach-role-policy --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
  aws iam delete-role-policy --role-name "$ROLE" --policy-name airsaws-bedrock-invoke 2>/dev/null || true
  aws iam delete-role --role-name "$ROLE"
else
  echo "    (already gone)"
fi
echo "Done."
