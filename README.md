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

NLBターゲットグループのヘルスチェックは `HTTP /healthz` を使用します。

---

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

---

## デプロイ手順

デプロイは **2回** に分けて行います。

### 第1回デプロイ — インフラ構築 & 証明書取得

このデプロイでは NLB (TCP:80 リスナーのみ) と EC2 などのインフラを構築します。  

```bash
npx cdk synth
npx cdk deploy
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
  --parameters CertificateArn=<第1回デプロイで取得したACM証明書ARN>
```

---

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

---

## 実装メモ（IP証明書対応）

IP証明書対応時にハマりやすい点を、記録としてまとめます。

- **Let's Encryptエンドポイントの扱い**
  - 利用するACMEディレクトリURLは `https://acme-v02.api.letsencrypt.org/directory`（本番）
  - ステージングは `https://acme-staging-v02.api.letsencrypt.org/directory`
  - プロファイル情報はディレクトリオブジェクトのトップレベルではなく `meta.profiles` 側にある

- **`acme` ライブラリのバージョンアップが必要だった理由**
  - `acme==2.11.0` では `ClientV2.new_order()` に `profile` 引数がなく、IP証明書必須の `shortlived` を指定できない
  - そのため `acme==5.3.1` に更新（合わせて `josepy>=2.0.0` / `cryptography>=43.0.0` へ更新）

- **上記以外に残しておくべきポイント**
  - `acme` 5系では例外・チャレンジAPIが一部変わっている（`ConflictError.location`、HTTP-01トークン取得）
  - IP証明書のCSRは `SAN=iPAddress` で作成し、IPを `Common Name` に入れない実装にしている
  - 現在の主な失敗要因はコードではなく HTTP-01 到達性（`Timeout during connect`）で、NLB:80 到達・nginx応答・経路制御の確認が必要
  - IP証明書は短期（約6日）なので、検証後は手動運用ではなく自動実行方式（EventBridgeなど）への移行を前提にする

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

# TypeScript コンパイル
npm run build

# CDK 合成（cdk-nag を含む検査）
npx cdk synth
```

---

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
