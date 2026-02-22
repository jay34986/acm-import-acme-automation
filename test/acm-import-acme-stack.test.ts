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
      Handler: 'handler.lambda_handler',
      Timeout: 300,
    });
  });
});
