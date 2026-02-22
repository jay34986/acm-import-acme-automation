import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AcmImportAcmeStack } from '../lib/acm-import-acme-stack';

describe('AcmImportAcmeStack', () => {
  test('NLB target group uses explicit health check path', () => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStack', {
      env: { region: 'ap-northeast-1' },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      Protocol: 'TCP',
      Port: 80,
      HealthCheckProtocol: 'HTTP',
      HealthCheckPath: '/healthz',
      HealthCheckPort: '80',
    });
  });

  test('EC2 UserData contains health endpoint and nginx config validation', () => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStackUserData', {
      env: { region: 'ap-northeast-1' },
    });

    const template = Template.fromStack(stack);
    const instances = template.findResources('AWS::EC2::Instance');

    const instance = Object.values(instances)[0] as {
      Properties: {
        UserData: unknown;
      };
    };

    const userDataJson = JSON.stringify(instance.Properties.UserData);

    expect(userDataJson).toContain('location = /healthz {');
    expect(userDataJson).toContain('return 200');
    expect(userDataJson).toContain('proxy_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;');
    expect(userDataJson).toContain('nginx -t');
    expect(userDataJson).toContain('systemctl enable --now nginx');
  });

  test('RenewCertLambda uses expected runtime and handler configuration', () => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStackLambda', {
      env: { region: 'ap-northeast-1' },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'python3.12',
      Architectures: ['arm64'],
      Handler: 'handler.lambda_handler',
      Timeout: 300,
    });
  });

  test('RenewCertLambda DOMAIN environment variable uses ACME FQDN from parameters', () => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStackAcmeDomain', {
      env: { region: 'ap-northeast-1' },
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: {
          DOMAIN: {
            'Fn::Join': [
              '',
              [
                {
                  Ref: 'NlbEip',
                },
                '.',
                {
                  Ref: 'AcmeDomainSuffix',
                },
              ],
            ],
          },
        },
      },
    });
  });

  test('RenewCertLambda ACME_DIRECTORY_URL environment variable is configurable by parameter', () => {
    const app = new cdk.App();
    const stack = new AcmImportAcmeStack(app, 'TestStackAcmeDirectoryUrl', {
      env: { region: 'ap-northeast-1' },
    });

    const template = Template.fromStack(stack);

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
