# 辐照校准包 COSE 复核台

审查员在网页粘贴 Ed25519 公钥与十六进制 COSE_Sign1 校准包，后端以**严格确定性 CBOR** 解析，
并用**原始受保护头字节与原始载荷**构造 `Sig_structure` 验签（绝不解析后重新序列化），
随后持久化复核记录，可按编号重新读取。

## 安全规则

- CBOR 必须为确定性编码：拒绝不定长编码、非最短整数、重复映射键、非规范键序、浮点数。
- 受保护头必须显式声明 `alg = EdDSA (-8)`，否则拒绝（未声明或其他算法一律拒绝）。
- 载荷必须是 UTF-8 编码的 JSON 对象。
- 验签使用包内原始字节：`["Signature1", raw(protected), h'', raw(payload)]`。
- 改动任一载荷字节、交换非规范键序、复用不匹配的签名，都会留下可查询的拒绝记录。

## 运行（Docker Compose）

```bash
# 启动页面与 API（宿主端口可通过 HOST_PORT 配置，默认 8000）
HOST_PORT=8080 docker compose up --build -d app

# 健康检查
curl http://localhost:8080/api/health

# 端到端验证：原始字节验签 + 非规范编码拒绝 + 构建检查 + HTTP 冒烟
# verify 服务执行后退出，退出码即检查结果（0 = 全部通过）
docker compose up --build --exit-code-from verify verify
echo "verify exit code: $?"
```

打开 `http://localhost:8080/` 使用复核页面。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/reviews` | 提交 `{public_key_hex, package_hex}`，返回复核记录（含编号、受保护头、载荷摘要、签名结论、逐项拒绝原因） |
| `GET` | `/api/reviews/{id}` | 按复核编号（如 `RV-000001`）重新读取记录 |
| `GET` | `/api/health` | 健康检查 |

## 本地开发（无 Docker）

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
REVIEW_DB=./data/reviews.db .venv/bin/uvicorn app.main:app --port 8000 &
APP_BASE_URL=http://localhost:8000 .venv/bin/python tests/verify.py
```

## 结构

```
app/
  cbor_strict.py   # 严格确定性 CBOR 解码器（保留每项原始字节切片）
  cose.py          # COSE_Sign1 结构检查 + 原始字节 Sig_structure 验签
  store.py         # SQLite 持久化（通过/拒绝记录均可按编号读取）
  main.py          # FastAPI：API 与页面
  static/index.html
tests/verify.py    # Compose verify 服务：端到端测试，退出码报告结果
Dockerfile  docker-compose.yml  requirements.txt
```
