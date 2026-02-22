#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AcmImportAcmeStack } from '../lib/acm-import-acme-stack';

const STACK_NAME = 'AcmImportAcmeStack';
const DEPLOY_REGION = 'ap-northeast-1';
const STACK_DESCRIPTION = 'ACM certificate import automation using ACME protocol (Let\'s Encrypt)';

const app = new cdk.App();

new AcmImportAcmeStack(app, STACK_NAME, {
  env: {
    region: DEPLOY_REGION,
  },
  description: STACK_DESCRIPTION,
});

cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
