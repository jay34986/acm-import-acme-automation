# acm-import-acme-automation

短期間化する証明書有効期間対応のために、ACMに外部取得した証明書をインポートし、ACMEクライアントをLambdaで実行して自動更新する検証用リポジトリです。

## 構成

```text
インターネット → NLB (TLS終端 / ACM証明書) → EC2 (HTTP / nginx)
```

- NLB は EIP を持つインターネット向け構成
- Lambda (ACMEクライアント) が HTTP-01 で証明書を取得して ACM へインポート
- EC2 nginx は `/.well-known/acme-challenge/` を S3 にプロキシ
- 証明書対象ドメインは `<NlbPublicIp>.<AcmeDomainSuffix>`
- NLBターゲットグループのヘルスチェックは `HTTP /healthz` を使用

| リソース | 内容 |
|---|---|
| VPC | シングルAZ、パブリックサブネットのみ (NAT GWなし) |
| EC2 (t4g.nano) | ARM64 / Amazon Linux 2023 / nginx (HTTP:80) |
| NLB | インターネット向け / EIPで固定IPを割り当て |
| EIP | NLBに割り当てる静的IPアドレス |
| ACM | NLBのTLSリスナーに設定するTLS証明書を格納 |
| Lambda (Python 3.12) | ACMEプロトコル (Let's Encrypt) で証明書を取得・更新 |
| Secrets Manager | ACMEアカウントキーおよびTLS証明書データを保管 |
| S3 | ACME HTTP-01チャレンジトークンの一時保管 |

## 前提条件

- AWS CLI および CDK CLI がインストール済みであること
- `aws login` 等で東京リージョン (`ap-northeast-1`) でAWS CLIが使用可能な状態であること
- Node.js 18 以上がインストール済みであること

## セットアップ

```bash
npm install
npx cdk bootstrap
npm run build
```

## デプロイ手順

デプロイは2回に分けて実施します。

### CDKパラメータ

| パラメータ | 用途 | 既定値 |
|---|---|---|
| `AcmeDomainSuffix` | 証明書対象FQDNのドメインサフィックス | `nip.io` |
| `AcmeDirectoryUrl` | ACMEディレクトリURL | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `CertificateArn` | NLB TLSリスナーに設定するACM証明書ARN（2回目デプロイで使用） | 空文字 |

### 第1回デプロイ（インフラ構築）

このデプロイでは NLB (TCP:80 リスナーのみ) と EC2 などのインフラを構築します。 
`AcmeDomainSuffix` はデフォルトで `nip.io` です。
`AcmeDirectoryUrl` は既定で Let’s Encrypt staging を使用します（検証向け）。

```bash
npx cdk synth
npx cdk deploy --require-approval never \
  --parameters AcmeDomainSuffix=nip.io
```

デプロイ後、CloudFormation 出力 `NlbAcmeFqdn` が証明書対象FQDNです。

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

`Timeout during connect (likely firewall problem)` が出る場合は、まず第1回デプロイを再実施して
Security Group / user-data の最新設定を反映し、以下で HTTP 到達性を確認してください。

```bash
NLB_PUBLIC_IP=$(aws cloudformation describe-stacks \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='NlbPublicIp'].OutputValue" \
  --output text)

CHALLENGE_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name AcmImportAcmeStack \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs[?OutputKey=='ChallengeBucketName'].OutputValue" \
  --output text)

TOKEN="preflight-$(date +%s)"
aws s3 cp <(printf 'ok') "s3://${CHALLENGE_BUCKET}/.well-known/acme-challenge/${TOKEN}" --region ap-northeast-1
curl -sS -D - "http://${NLB_PUBLIC_IP}.nip.io/.well-known/acme-challenge/${TOKEN}"
```

`HTTP/1.1 200` と本文 `ok` が返る状態であれば、HTTP-01 の前提を満たしています。

実行結果の `certificateArn` フィールドに ACM 証明書の ARN が記録されます。次のデプロイで使用します。

### 第2回デプロイ（NLB TLSリスナー有効化）

第1回デプロイで取得した ACM 証明書 ARN を `CertificateArn` パラメータに指定して再デプロイします。  
これにより NLB に TLS:443 リスナーが追加され、エンドツーエンドのHTTPS通信が有効になります。

```bash
npx cdk deploy --require-approval never \
  --parameters AcmeDomainSuffix=nip.io \
  --parameters CertificateArn=$(jq -r '.body | fromjson | .certificateArn' response.json)
```

## staging / production の切替

### 既定（staging）

既定値:

```text
https://acme-staging-v02.api.letsencrypt.org/directory
```

### production へ切替する場合

本番証明書を発行する場合のみ、`AcmeDirectoryUrl` を production URL に変更してデプロイします。

```bash
npx cdk deploy --require-approval never \
  --parameters AcmeDomainSuffix=nip.io \
  --parameters AcmeDirectoryUrl=https://acme-v02.api.letsencrypt.org/directory
```

> staging証明書はブラウザに信頼されません。動作確認用途として使用してください。

## Lambda環境変数

Lambda関数 (`RenewCertLambda`) の環境変数はCDKスタック定義から自動的に設定されます。  
手動で変更する場合は AWS マネジメントコンソールの Lambda 設定画面、または AWS CLI で更新してください。

| 環境変数 | 設定方法 | 説明 |
|---|---|---|
| `ACME_DIRECTORY_URL` | CDK固定値 | Let's Encrypt ACME URL |
| `ACME_ACCOUNT_SECRET_ARN` | CDK自動設定 | ACMEアカウント秘密鍵シークレットARN |
| `CERT_SECRET_ARN` | CDK自動設定 | 証明書データシークレットARN |
| `CHALLENGE_BUCKET` | CDK自動設定 | HTTP-01 トークン保存S3バケット |
| `DOMAIN` | CDK自動設定 | `<NlbPublicIp>.<AcmeDomainSuffix>` |
| `CERTIFICATE_ARN` | パラメータ | 再インポート時に既存証明書ARNを指定 |

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

## トラブルシュート

### `too many certificates ... for "<dynamic-dns-domain>"`

Let's Encrypt の登録ドメイン単位レート制限です。

対処:
- staging を使う（本リポジトリの既定）
- `AcmeDomainSuffix` を別の動的DNSサフィックスへ変更
- 本番運用時は独自ドメインを使用

### NLB ヘルスチェックが `unhealthy`

- EC2 で `nginx` が起動しているか確認
- `http://127.0.0.1/healthz` が `200` を返すか確認
- EC2 Security Group が `tcp/80` を受信可能か確認（NLBは送信元IPを保持）

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
```

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

- **Lambda の事前到達性チェック結果を確認**
  - 本実装では challenge 配信後に `http://<DOMAIN>/.well-known/acme-challenge/<token>` へ事前アクセスし、`200 + 本文一致` を確認してから ACME 応答します。
  - `HTTP-01 precheck failed` が返る場合は、ACME 側ではなく到達性（SG/NLB/nginx/S3）を優先して修正してください。

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
