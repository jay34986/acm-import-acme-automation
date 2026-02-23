#!/bin/bash

FQDN=$(aws cloudformation describe-stacks \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='NlbAcmeFqdn'].OutputValue" \
  --output text)
echo "FQDN: ${FQDN}"

LAMBDA_ARN=$(aws cloudformation describe-stacks \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='RenewCertLambdaArn'].OutputValue" \
  --output text)
echo "Lambda ARN: ${LAMBDA_ARN}"
echo ""

echo "*** Before Start ***"
curl --insecure -v "https://${FQDN}" |& grep -A 8 "Server certificate:" || true
echo ""

echo "*** Invoking Lambda to renew certificate ***"
aws lambda invoke --function-name "${LAMBDA_ARN}" --payload '{}' /tmp/response.json
echo ""

echo "*** Lambda invocation response ***"
jq -r '.body | fromjson' /tmp/response.json
echo ""
echo ""

sleep 240

echo "*** After Start ***"
curl --insecure -v "https://${FQDN}" |& grep -A 8 "Server certificate:" || true

rm /tmp/response.json
