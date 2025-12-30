package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "jwt_cli",
	Short: "JWT命令行工具 - 解密、生成和爆破JWT令牌",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

var decodeCmd = &cobra.Command{
	Use:   "decode [jwt_token]",
	Short: "解密JWT令牌（自动爆破密钥）",
	Long: `解密JWT令牌并验证签名

验证模式（优先级从高到低）：
  -s <密钥>      使用指定密钥验证签名
  -w <文件>      使用字典文件爆破
  无参数         使用内置84个常见弱密码自动爆破

示例：
  jwt_cli decode <token>                    # 内置字典爆破
  jwt_cli decode <token> -s mysecret        # 指定密钥验证
  jwt_cli decode <token> -w words.txt -t 8  # 外部字典爆破`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token := args[0]
		secret, _ := cmd.Flags().GetString("secret")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")
		DecodeJWT(token, secret, wordlist, threads)
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "生成JWT令牌",
	Long: `生成JWT令牌

参数：
  -p <json>      JWT载荷（必需），JSON格式
  -s <密钥>      签名密钥（默认：secret）
  -a <算法>      签名算法（默认：HS256）

支持算法：HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

示例：
  jwt_cli sign -p '{"sub":"user123","name":"Admin"}'
  jwt_cli sign -s mykey -p '{"user":"admin"}'
  jwt_cli sign -a HS512 -p '{"sub":"user123","exp":9999999999}'`,
	Run: func(cmd *cobra.Command, args []string) {
		secret, _ := cmd.Flags().GetString("secret")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		payload, _ := cmd.Flags().GetString("payload")
		GenerateJWT(secret, algorithm, payload)
	},
}

var crackCmd = &cobra.Command{
	Use:   "crack [jwt_token]",
	Short: "爆破JWT密钥",
	Long: `使用字典爆破JWT密钥

参数：
  -w <文件>      密码字典文件（必需）
  -t <线程数>    并发线程数（默认：1）

仅支持HMAC系列算法（HS256/HS384/HS512）

示例：
  jwt_cli crack <token> -w wordlist.txt
  jwt_cli crack <token> -w rockyou.txt -t 16`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token := args[0]
		wordlist, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")
		CrackJWT(token, wordlist, threads)
	},
}

func init() {
	// decode命令的参数
	decodeCmd.Flags().StringP("secret", "s", "", "验证签名的密钥")
	decodeCmd.Flags().StringP("wordlist", "w", "", "密码字典文件")
	decodeCmd.Flags().IntP("threads", "t", 4, "并发线程数")

	// sign命令的参数
	signCmd.Flags().StringP("secret", "s", "secret", "签名密钥")
	signCmd.Flags().StringP("algorithm", "a", "HS256", "签名算法")
	signCmd.Flags().StringP("payload", "p", "", "JWT载荷（JSON格式，必需）")
	signCmd.MarkFlagRequired("payload")

	// crack命令的参数
	crackCmd.Flags().StringP("wordlist", "w", "", "密码字典文件（必需）")
	crackCmd.Flags().IntP("threads", "t", 1, "并发线程数")

	rootCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(crackCmd)

	// 自定义help命令描述
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "查看命令帮助信息",
		Long:  `查看指定命令的详细帮助信息。不带参数时显示主帮助。`,
		Run: func(c *cobra.Command, args []string) {
			if len(args) == 0 {
				// 显示主帮助
				c.Root().Help()
				return
			}
			// 显示指定命令的帮助
			cmd, _, err := c.Root().Find(args)
			if err != nil {
				fmt.Printf("未找到命令: %s\n", args[0])
				os.Exit(1)
			}
			cmd.Help()
		},
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
