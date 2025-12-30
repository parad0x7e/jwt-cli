package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// defaultWordlist 内置密码字典（常见弱密码）
var defaultWordlist = []string{
	"secret",
	"password",
	"123456",
	"admin",
	"test",
	"12345678",
	"qwerty",
	"letmein",
	"password123",
	"admin123",
	"root",
	"toor",
	"test123",
	"pass",
	"welcome",
	"monkey",
	"dragon",
	"master",
	"hello",
	"freedom",
	"whatever",
	"qazwsx",
	"trustno1",
	"123456789",
	"abc123",
	"password1",
	"1234567890",
	"iloveyou",
	"princess",
	"adobe123",
	"123123",
	"admin1234",
	"password1234",
	"myspace1",
	"michael",
	"654321",
	"superman",
	"1qaz2wsx",
	"qwertyuiop",
	"ashley",
	"bailey",
	"shadow",
	"12345678910",
	"matthew",
	"jordan",
	"harley",
	"jessica",
	"andrew",
	"michelle",
	"charlie",
	"joshua",
	"nicholas",
	"starwars",
	"computer",
	"corvette",
	"pizza",
	"daniel",
	"access",
	"1234",
	"12345",
	"1234567",
	"jackson",
	"amanda",
	"sunshine",
	"tigger",
	"123qwe",
	"mustang",
	"football",
	"soccer",
	"batman",
	"qwe123",
	"123abc",
	"qwerty123",
	"passw0rd",
	"secret123",
	"mysecret",
	"secretkey",
	"key123",
	"jwtkey",
	"jwtsecret",
	"api_secret",
	"authkey",
	"authsecret",
	"token_secret",
}

// DecodeJWT 解密并显示JWT令牌
func DecodeJWT(tokenString, secret, wordlist string, threads int) {
	// 去除可能的Bearer前缀
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Printf("错误: 无效的JWT格式 (期望3部分，找到%d部分)\n", len(parts))
		return
	}

	fmt.Println("\n=== JWT 解密结果 ===\n")

	// 解码Header
	header, err := base64RawDecode(parts[0])
	if err != nil {
		fmt.Printf("解码Header失败: %v\n", err)
	} else {
		fmt.Printf("Header:\n%s\n\n", formatJSON(header))
	}

	// 解码Payload
	payload, err := base64RawDecode(parts[1])
	if err != nil {
		fmt.Printf("解码Payload失败: %v\n", err)
	} else {
		fmt.Printf("Payload:\n%s\n\n", formatJSON(payload))
	}

	// 显示签名
	fmt.Printf("Signature: %s\n", parts[2])

	// 尝试验证令牌（不验证签名）
	parsedToken, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		fmt.Printf("警告: 无法解析令牌 %v\n", err)
		return
	}

	// 检查过期时间
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			if time.Now().After(expTime) {
				fmt.Printf("\n⚠️  令牌已过期 (过期时间: %s)\n", expTime.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("\n✓ 令牌有效 (过期时间: %s)\n", expTime.Format("2006-01-02 15:04:05"))
			}
		}
	}

	// 签名验证
	fmt.Println("\n=== 签名验证 ===")

	// 优先使用指定密钥验证
	if secret != "" {
		fmt.Printf("使用指定密钥验证: %s\n", secret)
		if verifyJWT(tokenString, secret) {
			fmt.Println("✓ 签名验证成功！")
		} else {
			fmt.Println("✗ 签名验证失败！")
		}
		return
	}

	// 使用字典爆破（如果指定了字典文件，或者使用内置字典）
	if wordlist != "" {
		fmt.Printf("使用字典爆破密钥: %s (线程数: %d)\n", wordlist, threads)
		crackJWTQuiet(tokenString, wordlist, threads, false)
		return
	}

	// 未指定字典，使用内置字典爆破
	fmt.Printf("使用内置字典爆破密钥 (%d个密码, 线程数: %d)\n", len(defaultWordlist), threads)
	crackJWTQuietWithList(tokenString, defaultWordlist, threads, true)
}

// GenerateJWT 生成JWT令牌
func GenerateJWT(secret, algorithm, payloadStr string) {
	// 解析payload
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		fmt.Printf("错误: 无效的JSON格式: %v\n", err)
		fmt.Println("示例: {\"sub\":\"user123\",\"name\":\"John Doe\"}")
		return
	}

	// 设置claims
	claims := jwt.MapClaims{}
	for k, v := range payload {
		claims[k] = v
	}

	// 添加默认的iat和exp（如果不存在）
	if _, exists := claims["iat"]; !exists {
		claims["iat"] = time.Now().Unix()
	}
	if _, exists := claims["exp"]; !exists {
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	}

	// 创建token
	token := jwt.NewWithClaims(getSigningMethod(algorithm), claims)

	// 签名token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Printf("错误: 生成令牌失败: %v\n", err)
		return
	}

	fmt.Println("\n=== JWT生成成功 ===")
	fmt.Printf("算法: %s\n", algorithm)
	fmt.Printf("密钥: %s\n", secret)
	fmt.Printf("\n生成的JWT:\n%s\n\n", tokenString)
}

// CrackJWT 爆破JWT密钥
func CrackJWT(tokenString, wordlistPath string, threads int) {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Printf("错误: 无效的JWT格式\n")
		return
	}

	// 解码header获取算法
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("错误: 解码Header失败: %v\n", err)
		return
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("错误: 解析Header失败: %v\n", err)
		return
	}

	// 读取字典文件
	wordlist, err := os.ReadFile(wordlistPath)
	if err != nil {
		fmt.Printf("错误: 读取字典文件失败: %v\n", err)
		return
	}

	passwords := strings.Split(string(wordlist), "\n")
	total := len(passwords)

	fmt.Printf("\n=== JWT密钥爆破 ===\n")
	fmt.Printf("算法: %s\n", header.Alg)
	fmt.Printf("字典: %s (%d个密码)\n", wordlistPath, total)
	fmt.Printf("线程数: %d\n\n", threads)

	// 验证算法是否支持
	if !strings.HasPrefix(header.Alg, "HS") && !strings.HasPrefix(header.Alg, "RS") {
		fmt.Printf("警告: 不支持的算法 %s，仅支持HMAC和RSA系列\n", header.Alg)
		return
	}

	// 创建context用于取消
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建通道
	passwordChan := make(chan string, threads*100)
	resultChan := make(chan string, 1)

	var wg sync.WaitGroup
	startTime := time.Now()
	attempted := &atomicInt64{value: 0}

	// 启动worker
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case password, ok := <-passwordChan:
					if !ok {
						return
					}
					if password == "" {
						continue
					}

					count := attempted.increment()
					if count%1000 == 0 {
						fmt.Printf("\r已尝试: %d/%d (%.2f/s)", count, total,
							float64(count)/time.Since(startTime).Seconds())
					}

					if verifyJWT(tokenString, password) {
						select {
						case resultChan <- password:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

	// 发送密码到通道
	go func() {
		defer close(passwordChan)
		for _, password := range passwords {
			select {
			case <-ctx.Done():
				return
			case passwordChan <- password:
			}
		}
	}()

	// 等待结果或完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 处理结果
	if found, ok := <-resultChan; ok {
		elapsed := time.Since(startTime)
		fmt.Printf("\n\n✓ 找到密钥!\n")
		fmt.Printf("密钥: %s\n", found)
		fmt.Printf("耗时: %v\n", elapsed)
		fmt.Printf("尝试次数: %d\n", attempted.value)
	} else {
		elapsed := time.Since(startTime)
		fmt.Printf("\n\n✗ 未找到密钥\n")
		fmt.Printf("总尝试: %d\n", attempted.value)
		fmt.Printf("耗时: %v\n", elapsed)
	}
}

// crackJWTQuiet 静默爆破JWT密钥（用于decode命令，从文件读取）
func crackJWTQuiet(tokenString, wordlistPath string, threads int, isInternal bool) bool {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Printf("错误: 无效的JWT格式\n")
		return false
	}

	// 解码header获取算法
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("错误: 解码Header失败: %v\n", err)
		return false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("错误: 解析Header失败: %v\n", err)
		return false
	}

	// 读取字典文件
	wordlist, err := os.ReadFile(wordlistPath)
	if err != nil {
		fmt.Printf("错误: 读取字典文件失败: %v\n", err)
		return false
	}

	passwords := strings.Split(string(wordlist), "\n")
	return crackJWTQuietWithList(tokenString, passwords, threads, isInternal)
}

// crackJWTQuietWithList 使用密码列表爆破JWT密钥（用于内置字典）
func crackJWTQuietWithList(tokenString string, passwords []string, threads int, isInternal bool) bool {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		fmt.Printf("错误: 无效的JWT格式\n")
		return false
	}

	// 解码header获取算法
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("错误: 解码Header失败: %v\n", err)
		return false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		fmt.Printf("错误: 解析Header失败: %v\n", err)
		return false
	}

	total := len(passwords)

	// 验证算法是否支持
	if !strings.HasPrefix(header.Alg, "HS") && !strings.HasPrefix(header.Alg, "RS") {
		fmt.Printf("警告: 不支持的算法 %s，仅支持HMAC和RSA系列\n", header.Alg)
		return false
	}

	// 创建context用于取消
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建通道
	passwordChan := make(chan string, threads*100)
	resultChan := make(chan string, 1)

	var wg sync.WaitGroup
	startTime := time.Now()
	attempted := &atomicInt64{value: 0}

	// 启动worker
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case password, ok := <-passwordChan:
					if !ok {
						return
					}
					if password == "" {
						continue
					}

					count := attempted.increment()
					if count%1000 == 0 {
						fmt.Printf("\r进度: %d/%d (%.2f/s)", count, total,
							float64(count)/time.Since(startTime).Seconds())
					}

					if verifyJWT(tokenString, password) {
						select {
						case resultChan <- password:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

	// 发送密码到通道
	go func() {
		defer close(passwordChan)
		for _, password := range passwords {
			select {
			case <-ctx.Done():
				return
			case passwordChan <- password:
			}
		}
	}()

	// 等待结果或完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 处理结果
	if found, ok := <-resultChan; ok {
		elapsed := time.Since(startTime)
		fmt.Printf("\r✓ 找到密钥: %s (耗时: %v, 尝试: %d)\n", found, elapsed, attempted.value)
		return true
	} else {
		elapsed := time.Since(startTime)
		fmt.Printf("\n✗ 未找到密钥 (尝试: %d, 耗时: %v)\n", attempted.value, elapsed)
		return false
	}
}

// verifyJWT 验证JWT签名
func verifyJWT(tokenString, secret string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	return err == nil && token.Valid
}

// base64RawDecode Base64原始解码（处理无填充的情况）
func base64RawDecode(data string) (string, error) {
	// 添加填充
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// formatJSON 格式化JSON输出
func formatJSON(data string) string {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return data
	}
	formatted, _ := json.MarshalIndent(result, "  ", "  ")
	return string(formatted)
}

// getSigningMethod 获取签名方法
func getSigningMethod(alg string) jwt.SigningMethod {
	switch alg {
	case "HS256":
		return jwt.SigningMethodHS256
	case "HS384":
		return jwt.SigningMethodHS384
	case "HS512":
		return jwt.SigningMethodHS512
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodHS256
	}
}

// atomicInt64 原子计数器
type atomicInt64 struct {
	value int64
	mu    sync.Mutex
}

func (a *atomicInt64) increment() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.value++
	return a.value
}
