import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AcmImportAcmeStack } from '../lib/acm-import-acme-stack';

describe('AcmImportAcmeStack', () => {
  let template: Template;

  beforeEach(() => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStack', {
      env: { region: 'ap-northeast-1' },
    });
    template = Template.fromStack(stack);
  });

  describe('NLB', () => {
    test('ターゲットグループのヘルスチェックに HTTP /healthz を使用する', () => {
      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
        Protocol: 'TCP',
        Port: 80,
        HealthCheckProtocol: 'HTTP',
        HealthCheckPath: '/healthz',
        HealthCheckPort: '80',
      });
    });
  });

  describe('EC2', () => {
    test('UserData に nginx のヘルスエンドポイント・TLS検証・起動設定が含まれる', () => {
      const instances = template.findResources('AWS::EC2::Instance');
      const instance = Object.values(instances)[0];
      const userDataJson = JSON.stringify(instance.Properties.UserData);

      expect(userDataJson).toContain('location = /healthz {');
      expect(userDataJson).toContain('return 200');
      expect(userDataJson).toContain('proxy_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;');
      expect(userDataJson).toContain('nginx -t');
      expect(userDataJson).toContain('systemctl enable --now nginx');
    });

    test('Security Group がインターネットからの HTTP を許可する', () => {
      template.hasResourceProperties('AWS::EC2::SecurityGroup', {
        SecurityGroupIngress: [
          {
            CidrIp: '0.0.0.0/0',
            Description: 'Allow HTTP from internet clients via NLB (source IP preserved)',
            FromPort: 80,
            IpProtocol: 'tcp',
            ToPort: 80,
          },
        ],
      });
    });
  });

  describe('Lambda', () => {
    test('Python 3.12 ARM64 ランタイムとハンドラ設定を使用する', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'python3.12',
        Architectures: ['arm64'],
        Handler: 'handler.lambda_handler',
        Timeout: 300,
      });
    });

    test('DOMAIN 環境変数が EIP と AcmeDomainSuffix パラメータから構成される', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: {
            DOMAIN: {
              'Fn::Join': [
                '',
                [
                  { Ref: 'NlbEip' },
                  '.',
                  { Ref: 'AcmeDomainSuffix' },
                ],
              ],
            },
          },
        },
      });
    });

    test('ACME_DIRECTORY_URL 環境変数が AcmeDirectoryUrl パラメータで設定される', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: {
            ACME_DIRECTORY_URL: {
              Ref: 'AcmeDirectoryUrl',
            },
          },
        },
      });
    });
  });
});
