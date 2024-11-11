# JWT 認證服務器

這是一個使用 Go 語言實現的基於 JWT 的認證服務器，提供了用戶登入、訪問保護資源和登出功能。

## 功能特點

- JWT (JSON Web Token) 基於 Cookie 的身份驗證
- HttpOnly Cookie 保護，防止 XSS 攻擊
- 安全的 token 處理機制
- 統一的錯誤處理和響應格式
- 支持登出功能

## 技術棧

- Go 1.x
- github.com/golang-jwt/jwt/v5
- 標準庫 net/http

## 安裝和運行

1. 克隆項目：

``` bash
git clone git@github.com:NeroKuang/JWT_Practice.git
```

2. 安裝依賴：

``` bash
go mod tidy
```

3. 運行服務器：

``` bash
go run main.go
```

### 1. 登入
- 路徑: `/api/login`
- 方法: POST
- 請求體:
```json
{
    "username": "admin",
    "password": "password"
}
```
- 成功響應:
```json
{
    "status": "success",
    "message": "Login successful"
}
```

## 測試 API

使用 curl 測試 API：

1. 登入：
```bash
curl -X POST http://localhost:9999/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

2. 訪問保護資源：
```bash
curl -X GET http://localhost:9999/api/protected \
  --cookie "auth_token=<your-token>"
```

3. 登出：
```bash
curl -X POST http://localhost:9999/api/logout
```

## 目錄結構

```plaintext
.
├── main.go          # 主程序入口
├── README.md        # 項目文檔
└── go.mod          # Go 模塊文件
```
