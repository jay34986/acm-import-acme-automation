# acm-import-acme-automation

短期間化する証明書有効期間対応のために、ACMに外部取得した証明書をインポートし、ACMEクライアントをLambdaで実行して自動更新する検証用リポジトリです。

## 構成

```text
インターネット → NLB (TLS終端 / ACM証明書) → EC2 (HTTP / nginx)
```

- NLB は EIP を持つインターネット向け構成
- `DOMAIN` は `<NlbPublicIp>.sslip.io` を使用し、Let's Encrypt でドメイン証明書を発行
- Lambda (ACMEクライアント) が HTTP-01 で証明書を取得して ACM へインポート
- EC2 nginx は `/.well-known/acme-challenge/` を S3 にプロキシ

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

NLBターゲットグループのヘルスチェックは `HTTP /healthz` を使用します。

## 前提条件

- AWS CLI および CDK CLI がインストール済みであること
- `aws login` 等で東京リージョン (`ap-northeast-1`) でAWS CLIが使用可能な状態であること
- Node.js 18 以上がインストール済みであること

---

## セットアップ

```bash
npm install
npx cdk bootstrap
npm run build
```

## デプロイ手順

デプロイは **2回** に分けて行います。

### 第1回デプロイ — インフラ構築 & 証明書取得

このデプロイでは NLB (TCP:80 リスナーのみ) と EC2 などのインフラを構築します。  

```bash
npx cdk synth
npx cdk deploy
```

デプロイ後、`NlbSslipFqdn` が証明書の対象FQDNです。

### Lambda手動実行（証明書取得・ACMインポート）

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
npx cdk deploy \
  --parameters CertificateArn=$(jq -r '.body | fromjson | .certificateArn' response.json)
```
## Lambdaの環境変数

Lambda関数 (`RenewCertLambda`) の環境変数はCDKスタック定義から自動的に設定されます。  
手動で変更する場合は AWS マネジメントコンソールの Lambda 設定画面、または AWS CLI で更新してください。

| 環境変数 | 設定方法 | 説明 |
|---|---|---|
| `ACME_DIRECTORY_URL` | CDKにハードコード | Let's Encrypt のACMEディレクトリURL。本番: `https://acme-v02.api.letsencrypt.org/directory`、ステージング: `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `ACME_ACCOUNT_SECRET_ARN` | CDKが自動設定 | ACMEアカウント秘密鍵を保管する Secrets Manager シークレットの ARN |
| `CERT_SECRET_ARN` | CDKが自動設定 | 発行された証明書データ (cert / key / chain) を保管する Secrets Manager シークレットの ARN |
| `CHALLENGE_BUCKET` | CDKが自動設定 | ACME HTTP-01 チャレンジトークンを配置する S3 バケット名 |
| `DOMAIN` | CDKが自動設定 (`NlbPublicIp`) | 証明書を発行するIPアドレス (NLBに割り当てたEIP) |
| `CERTIFICATE_ARN` | `--parameters CertificateArn=` で設定 | 既存のACM証明書ARN (空の場合は新規インポート、指定した場合は上書き更新) |

`DOMAIN` がIPアドレスの場合、Lambdaは ACME の `shortlived` プロファイルを自動選択します。
Let's Encrypt のIP証明書は短期証明書プロファイルが必須のためです（有効期間は約6日）。

> `AWS_DEFAULT_REGION` は Lambda ランタイム予約済みのため、CDKで手動設定していません。ランタイムが自動で設定します。

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


## 検証コマンド

```bash
npm run build
npm run lint
npm test
npx cdk synth
```

## 証明書の更新

証明書の有効期限が近づいたら、Lambda を手動実行することで更新できます。  
`CERTIFICATE_ARN` が設定されていれば既存のACM証明書が上書き更新され、NLBへの再設定は不要です。

```bash
aws lambda invoke \
  --function-name <Lambda関数名> \
  --region ap-northeast-1 \
  --payload '{}' \
  response.json

## 費用を抑えるための補足

- 現状の `t4g.nano + single-AZ + NATなし` は、要件を満たしつつ安価な構成です。
- さらに抑える場合は、検証後にスタックを削除して従量課金を止める運用が有効です。

## トラブルシュート（NLBヘルスチェックがunhealthyになる場合）

第1回デプロイ後にターゲットが `unhealthy` の場合は、以下を確認してください。

1. **EC2でnginxが起動しているか**

```bash
INSTANCE_ID=$(aws cloudformation describe-stack-resources \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "StackResources[?LogicalResourceId=='WebServer'].PhysicalResourceId" \
  --output text)

aws ssm start-session --target "$INSTANCE_ID" --region ap-northeast-1

# EC2セッション内で実行
sudo systemctl status nginx
sudo nginx -t
```

2. **ヘルスチェックパスが応答するか**

```bash
# EC2セッション内で実行
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1/healthz
```

`200` が返ればヘルスチェックパスは正常です。

3. **Lambda実行で `No module named '_cffi_backend'` が出る場合**

Lambdaの依存ライブラリにネイティブ拡張 (`cryptography` / `cffi`) が含まれるため、
ローカル環境で作成した成果物を使うと Lambda 実行環境 (ARM64) と不整合になることがあります。

このリポジトリでは依存関係を ARM64 向けでバンドルする構成にしているため、
以下を再実行して関数を更新してください。

```bash
npm run build
npx cdk deploy
```

再デプロイ後に再度 Lambda を手動実行し、`FunctionError` が出ないことを確認してください。

4. **ACME HTTP-01 が `Timeout during connect` / `403 AccessDenied` になる場合**

IP証明書の検証で `/.well-known/acme-challenge/*` が失敗する場合、以下を順に確認してください。

- **NLBのSource IP保持に伴うSecurity Group設定**
  - NLB (instanceターゲット) はクライアントIPを保持してEC2へ転送します。
  - EC2のSecurity Groupで `tcp/80` をクライアント送信元から受けられる設定にしてください。
  - VPC CIDR のみ許可だと、外部からのHTTP-01検証が到達できず `Timeout` になります。

- **nginx の S3プロキシTLS検証設定**
  - `proxy_ssl_verify on;` を使う場合、`proxy_ssl_trusted_certificate` の指定が必要です。
  - 例: `/etc/pki/tls/certs/ca-bundle.crt`
  - 未設定だと nginx 起動時に `no proxy_ssl_trusted_certificate for proxy_ssl_verify` で失敗します。

- **S3 challengeプレフィックスの公開読取**
  - `/.well-known/acme-challenge/*` をS3へ `proxy_pass` する場合、Let's Encrypt からの取得は匿名アクセスになります。
  - バケット全体ではなく、`/.well-known/acme-challenge/*` のみ `s3:GetObject` を許可してください。
  - 未設定だと `403 AccessDenied` になります。

確認コマンド例:

```bash
curl -sS -D - http://<NlbPublicIp>/healthz
curl -sS -D - http://<NlbPublicIp>/.well-known/acme-challenge/<token>
```

`/healthz` が `200`、challengeパスが `200` でトークン本文を返せる状態になれば、HTTP-01の前提は満たせます。
