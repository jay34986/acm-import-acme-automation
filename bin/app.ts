#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AcmImportAcmeStack } from '../lib/acm-import-acme-stack';

const app = new cdk.App();

new AcmImportAcmeStack(app, 'AcmImportAcmeStack', {
  env: {
    region: 'ap-northeast-1',
  },
  description: 'ACM certificate import automation using ACME protocol (Let\'s Encrypt)',
});

cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
