# acm-import-acme-automation

短期間化する証明書有効期間対応のために、ACMに外部取得した証明書をインポートし、ACMEクライアントをLambdaで実行して自動更新する検証用リポジトリ。

---

## 構成

```
インターネット → NLB (TLS終端 / ACM証明書) → EC2 (HTTP / nginx)
```

| リソース | 内容 |
|---|---|
| VPC | シングルAZ、パブリックサブネットのみ (NAT GWなし) |
| EC2 (t4g.nano) | ARM64 / Amazon Linux 2023 / nginx (HTTP:80) |
| NLB | インターネット向け / EIPで固定IPを割り当て |
| EIP | NLBに割り当てる静的IPアドレス (証明書のサブジェクト) |
| ACM | NLBのTLSリスナーに設定するIP証明書を格納 |
| Lambda (Python 3.12) | ACMEプロトコル (Let's Encrypt) で証明書を取得・更新 |
| Secrets Manager | ACMEアカウントキーおよびTLS証明書データを保管 |
| S3 | ACME HTTP-01チャレンジトークンの一時保管 |

---

## 前提条件

- AWS CLI および CDK CLI がインストール済みであること
- `cdk bootstrap` が対象アカウント・東京リージョン (`ap-northeast-1`) で実行済みであること
- Node.js 18 以上がインストール済みであること

---

## セットアップ

```bash
npm install
npm run build
```

---

## デプロイ手順

デプロイは **2回** に分けて行います。

### 第1回デプロイ — インフラ構築 & 証明書取得

このデプロイでは NLB (TCP:80 リスナーのみ) と EC2 などのインフラを構築します。  
`Domain` パラメータには、NLBのEIPに割り当てるIPアドレスまたはドメイン名を指定してください。

```bash
cdk deploy \
  --parameters Domain=<EIPのIPアドレスまたはドメイン名>
```

> **ヒント**: デプロイ完了後、出力の `NlbPublicIp` に表示される静的IPアドレスが証明書のサブジェクトになります。

デプロイ完了後、Lambda (`RenewCertLambda`) を手動実行して証明書を取得します。

```bash
# Lambda関数名を取得
LAMBDA_ARN=$(aws cloudformation describe-stacks \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='RenewCertLambdaArn'].OutputValue" \
  --output text)

# Lambda を手動実行
aws lambda invoke \
  --function-name "$LAMBDA_ARN" \
  --region ap-northeast-1 \
  --payload '{}' \
  response.json

cat response.json
```

実行結果の `certificateArn` フィールドに ACM 証明書の ARN が記録されます。次のデプロイで使用します。

---

### 第2回デプロイ — NLB TLSリスナーの設定

第1回デプロイで取得した ACM 証明書 ARN を `CertificateArn` パラメータに指定して再デプロイします。  
これにより NLB に TLS:443 リスナーが追加され、エンドツーエンドのHTTPS通信が有効になります。

```bash
cdk deploy \
  --parameters Domain=<EIPのIPアドレスまたはドメイン名> \
  --parameters CertificateArn=<第1回デプロイで取得したACM証明書ARN>
```

---

## Lambdaの環境変数

Lambda関数 (`RenewCertLambda`) の環境変数はCDKスタックのパラメータから自動的に設定されます。  
手動で変更する場合は AWS マネジメントコンソールの Lambda 設定画面、または AWS CLI で更新してください。

| 環境変数 | 設定方法 | 説明 |
|---|---|---|
| `ACME_DIRECTORY_URL` | CDKにハードコード | Let's Encrypt のACMEディレクトリURL。本番: `https://acme-v02.api.letsencrypt.org/directory`、ステージング: `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `ACME_ACCOUNT_SECRET_ARN` | CDKが自動設定 | ACMEアカウント秘密鍵を保管する Secrets Manager シークレットの ARN |
| `CERT_SECRET_ARN` | CDKが自動設定 | 発行された証明書データ (cert / key / chain) を保管する Secrets Manager シークレットの ARN |
| `CHALLENGE_BUCKET` | CDKが自動設定 | ACME HTTP-01 チャレンジトークンを配置する S3 バケット名 |
| `DOMAIN` | `--parameters Domain=` で設定 | 証明書を発行するIPアドレスまたはドメイン名 |
| `CERTIFICATE_ARN` | `--parameters CertificateArn=` で設定 | 既存のACM証明書ARN (空の場合は新規インポート、指定した場合は上書き更新) |
| `AWS_DEFAULT_REGION` | CDKにハードコード | AWSリージョン (`ap-northeast-1`) |

### ステージング環境でのテスト

Let's Encrypt のレート制限を避けるため、初回はステージング環境で動作確認することを推奨します。  
`ACME_DIRECTORY_URL` を以下のように変更してください。

```bash
aws lambda update-function-configuration \
  --function-name <Lambda関数名> \
  --region ap-northeast-1 \
  --environment "Variables={ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory,...}"
```

> ステージング証明書はブラウザに信頼されません。動作確認後は本番URLに戻してください。

---

## 証明書の更新

証明書の有効期限が近づいたら、Lambda を手動実行することで更新できます。  
`CERTIFICATE_ARN` が設定されていれば既存のACM証明書が上書き更新され、NLBへの再設定は不要です。

```bash
aws lambda invoke \
  --function-name <Lambda関数名> \
  --region ap-northeast-1 \
  --payload '{}' \
  response.json
```

---

## スタティック解析

```bash
# TypeScript (ESLint)
npm run lint

# CDK (cdk-nag) — cdk synthesize時に自動実行
npm run build
```
