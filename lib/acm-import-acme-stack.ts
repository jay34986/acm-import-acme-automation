import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';
import * as path from 'path';

export class AcmImportAcmeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // -------------------------------------------------------------------------
    // Stack Parameter: target domain / IP address for the certificate
    // -------------------------------------------------------------------------
    const domainParam = new cdk.CfnParameter(this, 'Domain', {
      type: 'String',
      description: 'Domain name or IP address to issue the TLS certificate for (e.g. 203.0.113.1)',
      default: 'example.com',
    });

    // -------------------------------------------------------------------------
    // Stack Parameter: ACM certificate ARN for the NLB TLS listener
    // -------------------------------------------------------------------------
    const certArnParam = new cdk.CfnParameter(this, 'CertificateArn', {
      type: 'String',
      description:
        'ACM certificate ARN to attach to the NLB TLS listener (port 443). ' +
        'Leave empty on initial deploy; run RenewCertLambda first to obtain the certificate, ' +
        'then redeploy with this value.',
      default: '',
    });

    // Condition: only create the TLS listener when a certificate ARN is provided
    const hasCert = new cdk.CfnCondition(this, 'HasCertificate', {
      expression: cdk.Fn.conditionNot(
        cdk.Fn.conditionEquals(certArnParam.valueAsString, ''),
      ),
    });

    // -------------------------------------------------------------------------
    // VPC: single AZ, public subnet only (no NAT GW to save cost)
    // -------------------------------------------------------------------------
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
      ],
      flowLogs: {
        VpcFlowLog: {
          destination: ec2.FlowLogDestination.toCloudWatchLogs(),
          trafficType: ec2.FlowLogTrafficType.ALL,
        },
      },
    });

    NagSuppressions.addResourceSuppressions(vpc, [
      {
        id: 'AwsSolutions-VPC7',
        reason: 'VPC flow logs are enabled; cost-optimised single-AZ public-only VPC for a small web server',
      },
    ]);

    // -------------------------------------------------------------------------
    // S3 Bucket: ACME HTTP-01 challenge tokens
    // -------------------------------------------------------------------------
    const accessLogsBucket = new s3.Bucket(this, 'ChallengeAccessLogsBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    NagSuppressions.addResourceSuppressions(accessLogsBucket, [
      {
        id: 'AwsSolutions-S1',
        reason: 'This is the access logs bucket itself; it does not need its own access logging',
      },
    ]);

    const challengeBucket = new s3.Bucket(this, 'ChallengeBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: false,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'challenge-bucket/',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    NagSuppressions.addResourceSuppressions(challengeBucket, [
      {
        id: 'AwsSolutions-S2',
        reason: 'Public access is intentionally blocked; nginx proxies .well-known/acme-challenge/ to S3 via IAM',
      },
    ]);

    // -------------------------------------------------------------------------
    // Secrets Manager: ACME account private key
    // -------------------------------------------------------------------------
    const acmeAccountSecret = new secretsmanager.Secret(this, 'AcmeAccountSecret', {
      description: 'ACME account private key (PEM) for Let\'s Encrypt',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ key: '' }),
        generateStringKey: '_unused',
      },
    });

    // -------------------------------------------------------------------------
    // Secrets Manager: TLS certificate data (cert + key + chain)
    // -------------------------------------------------------------------------
    const certSecret = new secretsmanager.Secret(this, 'CertSecret', {
      description: 'TLS certificate data: certificate, private key, and chain',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ certificate: '', privateKey: '', chain: '' }),
        generateStringKey: '_unused',
      },
    });

    // -------------------------------------------------------------------------
    // IAM Role for Lambda
    // -------------------------------------------------------------------------
    const lambdaRole = new iam.Role(this, 'RenewCertLambdaRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for the certificate renewal Lambda',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    lambdaRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AcmPermissions',
      actions: [
        'acm:ImportCertificate',
        'acm:ListCertificates',
        'acm:DescribeCertificate',
      ],
      resources: ['*'],
    }));

    lambdaRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SecretsManagerPermissions',
      actions: [
        'secretsmanager:GetSecretValue',
        'secretsmanager:PutSecretValue',
        'secretsmanager:UpdateSecret',
      ],
      resources: [
        acmeAccountSecret.secretArn,
        certSecret.secretArn,
      ],
    }));

    lambdaRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ChallengeBucketPermissions',
      actions: [
        's3:PutObject',
        's3:GetObject',
        's3:DeleteObject',
      ],
      resources: [challengeBucket.arnForObjects('*')],
    }));

    NagSuppressions.addResourceSuppressions(lambdaRole, [
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWSLambdaBasicExecutionRole is the minimal managed policy for Lambda CloudWatch Logs access',
      },
      {
        id: 'AwsSolutions-IAM5',
        reason: 'acm:ListCertificates and acm:ImportCertificate require wildcard resource for new certificate creation; S3 object-level permissions are scoped to the challenge bucket',
      },
    ], true);

    // -------------------------------------------------------------------------
    // Lambda: Certificate Renewal
    // -------------------------------------------------------------------------
    const renewCertLambda = new lambda.Function(this, 'RenewCertLambda', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/renew_certificate')),
      role: lambdaRole,
      timeout: cdk.Duration.minutes(5),
      memorySize: 256,
      description: 'Renews TLS certificates via ACME (Let\'s Encrypt) and imports them to ACM',
      environment: {
        ACME_DIRECTORY_URL: 'https://acme-v02.api.letsencrypt.org/directory',
        ACME_ACCOUNT_SECRET_ARN: acmeAccountSecret.secretArn,
        CERT_SECRET_ARN: certSecret.secretArn,
        CHALLENGE_BUCKET: challengeBucket.bucketName,
        DOMAIN: domainParam.valueAsString,
        CERTIFICATE_ARN: certArnParam.valueAsString,
        AWS_DEFAULT_REGION: 'ap-northeast-1',
      },
    });

    NagSuppressions.addResourceSuppressions(renewCertLambda, [
      {
        id: 'AwsSolutions-L1',
        reason: 'Python 3.12 is the latest stable runtime for this Lambda function',
      },
    ]);

    NagSuppressions.addResourceSuppressionsByPath(
      this,
      `/${this.stackName}/RenewCertLambda/Resource`,
      [
        {
          id: 'AwsSolutions-VPC3',
          reason: 'Lambda is intentionally not placed in a VPC to avoid NAT Gateway costs; it uses IAM-scoped permissions',
        },
      ],
    );

    // -------------------------------------------------------------------------
    // Security Group for EC2 (HTTP from VPC only; TLS is terminated at the NLB)
    // -------------------------------------------------------------------------
    const webServerSg = new ec2.SecurityGroup(this, 'WebServerSg', {
      vpc,
      description: 'Security group for the ACME web server (HTTP from VPC only; TLS terminated at NLB)',
      allowAllOutbound: true,
    });

    // Allow HTTP from within the VPC (NLB-to-EC2 traffic and NLB health checks)
    webServerSg.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(80),
      'Allow HTTP from VPC (NLB to EC2)',
    );

    // -------------------------------------------------------------------------
    // IAM Role for EC2
    // -------------------------------------------------------------------------
    const ec2Role = new iam.Role(this, 'WebServerRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'EC2 instance role for the ACME web server',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    });

    ec2Role.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadChallengeBucket',
      actions: ['s3:GetObject'],
      resources: [challengeBucket.arnForObjects('*')],
    }));

    NagSuppressions.addResourceSuppressions(ec2Role, [
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AmazonSSMManagedInstanceCore is required for Systems Manager Session Manager access (replaces SSH)',
      },
      {
        id: 'AwsSolutions-IAM5',
        reason: 'S3 GetObject on challenge bucket objects requires wildcard path',
      },
    ], true);

    const instanceProfile = new iam.InstanceProfile(this, 'WebServerInstanceProfile', {
      role: ec2Role,
    });

    // -------------------------------------------------------------------------
    // EC2 User Data (nginx serves plain HTTP; TLS is terminated at the NLB)
    // -------------------------------------------------------------------------
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      '#!/bin/bash',
      'set -euo pipefail',

      // Install nginx
      'dnf update -y',
      'dnf install -y nginx',

      // Write nginx config
      'cat > /etc/nginx/conf.d/acme.conf << \'NGINXEOF\'',
      'server {',
      '    listen 80;',
      '    server_name _;',
      '',
      '    # Proxy ACME HTTP-01 challenge tokens to S3',
      '    location /.well-known/acme-challenge/ {',
      '        proxy_pass https://s3.ap-northeast-1.amazonaws.com/${CHALLENGE_BUCKET}/.well-known/acme-challenge/;',
      '        proxy_set_header Host s3.ap-northeast-1.amazonaws.com;',
      '        proxy_ssl_verify on;',
      '    }',
      '',
      '    location / {',
      '        root   /usr/share/nginx/html;',
      '        index  index.html index.htm;',
      '    }',
      '}',
      'NGINXEOF',

      // Substitute CHALLENGE_BUCKET placeholder in nginx config
      `CHALLENGE_BUCKET_NAME="${challengeBucket.bucketName}"`,
      'sed -i "s/\\${CHALLENGE_BUCKET}/$CHALLENGE_BUCKET_NAME/g" /etc/nginx/conf.d/acme.conf',

      // Remove default server config to avoid conflicts
      'rm -f /etc/nginx/conf.d/default.conf',

      // Enable and start nginx
      'systemctl enable nginx',
      'systemctl start nginx',
    );

    // -------------------------------------------------------------------------
    // EC2 Instance: t4g.nano, ARM64, Amazon Linux 2023
    // -------------------------------------------------------------------------
    const instance = new ec2.Instance(this, 'WebServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.NANO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
      }),
      securityGroup: webServerSg,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      userData,
      userDataCausesReplacement: true,
      requireImdsv2: true,
      instanceProfile,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(8, {
            encrypted: true,
          }),
        },
      ],
    });

    NagSuppressions.addResourceSuppressions(instance, [
      {
        id: 'AwsSolutions-EC28',
        reason: 'Detailed monitoring is not enabled to minimise cost for this small t4g.nano instance',
      },
      {
        id: 'AwsSolutions-EC29',
        reason: 'Auto Scaling is intentionally not used; this is a single-instance cost-optimised web server',
      },
    ]);

    // -------------------------------------------------------------------------
    // Elastic IP for the NLB (static IP used as the subject for the certificate)
    // -------------------------------------------------------------------------
    const nlbEip = new ec2.CfnEIP(this, 'NlbEip', {
      domain: 'vpc',
    });

    // -------------------------------------------------------------------------
    // Network Load Balancer (TLS terminated here; forwards plain HTTP to EC2)
    // Use CfnLoadBalancer (L1) to assign the EIP via SubnetMappings.
    // -------------------------------------------------------------------------
    const cfnNlb = new elbv2.CfnLoadBalancer(this, 'Nlb', {
      type: 'network',
      scheme: 'internet-facing',
      subnetMappings: [{
        subnetId: vpc.publicSubnets[0].subnetId,
        allocationId: nlbEip.attrAllocationId,
      }],
      loadBalancerAttributes: [
        { key: 'load_balancing.cross_zone.enabled', value: 'false' },
        { key: 'access_logs.s3.enabled', value: 'false' },
      ],
    });

    NagSuppressions.addResourceSuppressions(cfnNlb, [
      {
        id: 'AwsSolutions-ELB2',
        reason: 'NLB access logs are disabled to minimise cost for this validation environment',
      },
    ]);

    // -------------------------------------------------------------------------
    // NLB Target Group: EC2 on port 80
    // -------------------------------------------------------------------------
    const cfnTargetGroup = new elbv2.CfnTargetGroup(this, 'WebTargetGroup', {
      vpcId: vpc.vpcId,
      protocol: 'TCP',
      port: 80,
      targetType: 'instance',
      targets: [{ id: instance.instanceId }],
      healthCheckProtocol: 'HTTP',
      healthCheckPath: '/',
      healthCheckPort: '80',
    });

    // -------------------------------------------------------------------------
    // NLB Listener: TCP port 80 (ACME HTTP-01 challenge pass-through)
    // -------------------------------------------------------------------------
    new elbv2.CfnListener(this, 'HttpListener', {
      loadBalancerArn: cfnNlb.ref,
      protocol: 'TCP',
      port: 80,
      defaultActions: [{
        type: 'forward',
        targetGroupArn: cfnTargetGroup.ref,
      }],
    });

    // -------------------------------------------------------------------------
    // NLB Listener: TLS port 443 (created only when CertificateArn is provided)
    // -------------------------------------------------------------------------
    const cfnTlsListener = new elbv2.CfnListener(this, 'TlsListener', {
      loadBalancerArn: cfnNlb.ref,
      protocol: 'TLS',
      port: 443,
      sslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06',
      certificates: [{ certificateArn: certArnParam.valueAsString }],
      defaultActions: [{
        type: 'forward',
        targetGroupArn: cfnTargetGroup.ref,
      }],
    });
    cfnTlsListener.cfnOptions.condition = hasCert;

    // -------------------------------------------------------------------------
    // Stack Outputs
    // -------------------------------------------------------------------------
    new cdk.CfnOutput(this, 'NlbPublicIp', {
      value: nlbEip.ref,
      description: 'Static Elastic IP address of the Network Load Balancer',
    });

    new cdk.CfnOutput(this, 'NlbDnsName', {
      value: cfnNlb.attrDnsName,
      description: 'DNS name of the Network Load Balancer',
    });

    new cdk.CfnOutput(this, 'ChallengeBucketName', {
      value: challengeBucket.bucketName,
      description: 'S3 bucket for ACME HTTP-01 challenge tokens',
    });

    new cdk.CfnOutput(this, 'AcmeAccountSecretArn', {
      value: acmeAccountSecret.secretArn,
      description: 'Secrets Manager ARN for the ACME account private key',
    });

    new cdk.CfnOutput(this, 'CertSecretArn', {
      value: certSecret.secretArn,
      description: 'Secrets Manager ARN for the TLS certificate data',
    });

    new cdk.CfnOutput(this, 'RenewCertLambdaArn', {
      value: renewCertLambda.functionArn,
      description: 'Lambda function ARN for certificate renewal',
    });
  }
}
