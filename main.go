package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
)

// 系統常量定義
const (
	PORT       = ":9999"    // 服務器監聽端口
	TOKEN_EXP  = time.Hour * 24  // Token有效期為24小時
	AUTH_USER  = "admin"    // 測試用戶名
	AUTH_PASS  = "password" // 測試密碼
)

// JWT密鑰（在實際應用中應該從環境變量或配置文件中讀取）
var secretKey = []byte("secret")

// User 用戶模型
type User struct {
	Username string `json:"username"` // 用戶名
	Password string `json:"password"` // 密碼
}

// Response API響應結構
type Response struct {
	Status  string      `json:"status"`            // 狀態：success/error
	Message string      `json:"message,omitempty"` // 提示信息
	Data    interface{} `json:"data,omitempty"`    // 響應數據
	Error   string      `json:"error,omitempty"`   // 錯誤信息
}

// JWT相關函數
// createToken 創建JWT令牌
// JWT (JSON Web Token) 包含三個部分：
// 1. Header: 包含算法信息
// 2. Payload: 包含用戶信息和過期時間
// 3. Signature: 使用密鑰進行簽名，確保token的完整性
// @param username 用戶名
// @return tokenString 生成的JWT字符串
// @return error 可能的錯誤信息
func createToken(username string) (string, error) {
	// 1. 創建token聲明
	claims := jwt.MapClaims{
		"username": username,                         // 設置用戶名
		"exp":     time.Now().Add(TOKEN_EXP).Unix(), // 設置過期時間
	}
	
	// 2. 使用HS256算法創建token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 3. 使用密鑰對token進行簽名
	return token.SignedString(secretKey)
}

// verifyToken 驗證JWT令牌
// @param tokenString 待驗證的token字符串
// @return 用戶名和可能的錯誤
func verifyToken(tokenString string) (string, error) {
	// 1. 移除Bearer前綴（如果存在）
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// 2. 解析token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 2.1 驗證簽名方法是否為HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return "", err
	}

	// 3. 驗證token並提取用戶名
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username, ok := claims["username"].(string)
		if !ok {
			return "", errors.New("invalid username claim")
		}
		return username, nil
	}

	return "", errors.New("invalid token")
}

// LoginHandler 處理用戶登入請求
// @param w 響應寫入器
// @param r 請求對象
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 驗證HTTP方法
	if r.Method != http.MethodPost {
		sendResponse(w, http.StatusMethodNotAllowed, Response{
			Status: "error",
			Error:  "method not allowed",
		})
		return
	}

	// 2. 解析請求體
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		sendResponse(w, http.StatusBadRequest, Response{
			Status: "error",
			Error:  "invalid request body",
		})
		return
	}

	// 3. 驗證用戶憑證
	if user.Username == AUTH_USER && user.Password == AUTH_PASS {
		// 3.1 生成JWT token
		token, err := createToken(user.Username)
		if err != nil {
			sendResponse(w, http.StatusInternalServerError, Response{
				Status: "error",
				Error:  "failed to create token",
			})
			return
		}

		// 3.2 設置 HttpOnly Cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			HttpOnly: true,           // 防止JavaScript訪問
			Secure:   true,           // 只在HTTPS下傳輸
			SameSite: http.SameSiteStrictMode,  // 防止CSRF攻擊
			Path:     "/",
			MaxAge:   int(TOKEN_EXP.Seconds()),
		})

		// 3.3 返回成功響應（不再直接返回token）
		sendResponse(w, http.StatusOK, Response{
			Status:  "success",
			Message: "Login successful",
		})
		return
	}

	// 3.3 認證失敗響應
	sendResponse(w, http.StatusUnauthorized, Response{
		Status: "error",
		Error:  "invalid credentials",
	})
}

// ProtectedHandler 處理需要認證的請求
// @param w 響應寫入器
// @param r 請求對象
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 驗證HTTP方法
	if r.Method != http.MethodGet {
		sendResponse(w, http.StatusMethodNotAllowed, Response{
			Status: "error",
			Error:  "method not allowed",
		})
		return
	}

	// 2. 從Cookie中獲取token
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		sendResponse(w, http.StatusUnauthorized, Response{
			Status: "error",
			Error:  "no token provided",
		})
		return
	}

	// 3. 驗證token
	username, err := verifyToken(cookie.Value)
	if err != nil {
		sendResponse(w, http.StatusUnauthorized, Response{
			Status: "error",
			Error:  "invalid token",
		})
		return
	}

	// 4. 返回成功響應
	sendResponse(w, http.StatusOK, Response{
		Status:  "success",
		Message: "Protected resource accessed",
		Data: map[string]string{
			"username": username,
		},
	})
}

// LogoutHandler 添加登出處理
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// 清除Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		MaxAge:   -1,  // 立即過期
	})

	sendResponse(w, http.StatusOK, Response{
		Status:  "success",
		Message: "Logout successful",
	})
}

// sendResponse 統一的響應發送函數
// @param w 響應寫入器
// @param statusCode HTTP狀態碼
// @param response 響應內容
func sendResponse(w http.ResponseWriter, statusCode int, response Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// 主函數
func main() {
	// 1. 註冊API路由
	http.HandleFunc("/api/login", LoginHandler)     // 登入接口
	http.HandleFunc("/api/logout", LogoutHandler)    // 登出接口
	http.HandleFunc("/api/protected", ProtectedHandler) // 受保護的接口

	// 2. 啟動HTTP服務器
	fmt.Printf("Server is running on port %s\n", PORT)
	if err := http.ListenAndServe(PORT, nil); err != nil {
		fmt.Printf("Server failed to start: %v\n", err)
	}
}
