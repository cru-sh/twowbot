package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/aimerny/kook-go/app/common"
	"github.com/aimerny/kook-go/app/core/action"
	"github.com/aimerny/kook-go/app/core/event"
	"github.com/aimerny/kook-go/app/core/model"
	"github.com/aimerny/kook-go/app/core/session"
)

func main() {

	urls := []string{
		//	"https://dreamo.happydoghouse.link/query?f=gm.log&q=&l=10000",
		"https://ringo.happydoghouse.link/query?f=gm.log&q=&l=10000",
		"https://hoggo.happydoghouse.link/query?f=gm.log&q=&l=10000",
		"https://ravo.happydoghouse.link/query?f=gm.log&q=&l=10000",
		// 添加更多 URL
	}

	username := "k8ok8o"
	password := "C9GS5UUzFqmmDQH8NEUP"

	// 测试机器人
	//kooktoken := "1/MjM0OTY=/PqEFBx0mZWWFOUmmv5crWw=="

	//TWOW-GMBOT
	kooktoken := "1/MzY2NzU=/f24dlJn+iwQu5A5sQqaeZA=="

	//测试渠道
	//koooktargetid := "2542015504189926"

	//播报频道
	koooktargetid := "2650771093403308"

	//C/GM管理频道
	//koooktargetid := "9225622321653596"

	//Bot
	common.InitLogger()

	// 异步启动Kook会话
	go func() {
		session, err := session.CreateSession(kooktoken, true)
		if err != nil {
			log.Errorf("Failed to create Kook session: %s", err)
			return
		}
		session.RegisterEventHandler(&MyEventHandler{})
		session.Start() // Start()没有返回值
	}()

	// 初始化PocketBase
	app := pocketbase.New()

	// 设置环境变量
	os.Setenv("PB_DEBUG", "true")
	os.Setenv("PB_DATA_DIR", "./pb_data")
	os.Setenv("PB_ENCRYPTION_ENV", "PB_ENCRYPTION_KEY")

	// 启用API访问
	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		// 静态文件服务
		e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS("./pb_public"), false))

		// 添加数据库API路由
		e.Router.GET("/api/security-alerts", func(c echo.Context) error {
			// 需要认证
			auth := c.Request().Header.Get("Authorization")
			if auth != "Bearer your-secret-token" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			}

			// 获取所有安全警报记录
			records, err := app.Dao().FindRecordsByFilter("security_alerts", "", "-created", 0, 0)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			return c.JSON(http.StatusOK, records)
		}, apis.RequireAdminAuth())

		// 添加健康检查端点
		e.Router.GET("/health", func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
		})

		return nil
	})

	// 确保数据目录存在
	if err := os.MkdirAll("./pb_data", 0755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	// 当gm_actions创建条目触发
	app.OnModelAfterCreate("gm_actions").Add(func(e *core.ModelEvent) error {
		log.Println(e.Model.TableName())
		log.Println(e.Model.GetId())

		// Cast the model to a Record to access its data map
		if record, ok := e.Model.(*models.Record); ok {

			log.Println("Data:", record.GetString("gm_command"))

			actionType := record.GetString("action_type")
			title := ""
			switch actionType {
			case "ban":
				title = "封禁公告"
			case "mute":
				title = "禁言公告"
			case "kick":
				title = "踢出公告"
			case "warn":
				title = "警告公告"
			case "jail":
				title = "监禁公告"
			default:
				title = "GM操作公告"
			}

			maskedAccount, err := MaskAccount(record.GetString("player_acc"))
			duration, err := parseTime(record.GetString("action_duration"))

			// 检查被盗号风险
			isHijackRisk := checkAccountHijackRisk(record.GetString("player_acc"),
				record.GetString("date"), "")

			modules := []model.CardModule{
				// 第一部分: 带有 kmarkdown 的 section
				*model.NewKMarkdown(fmt.Sprintf("**(font)[%s](font)[purple]%s - 风险等级:%d/10:**\n",
					record.GetString("server"),
					title,
					record.GetInt("risk_weight"))),

				// 第二部分: 包含多个字段的 section
				{
					Type: "section",
					Text: model.CardText{
						Type: "paragraph",
						Cols: 3,
						Fields: []model.CardText{
							{
								Type:    "kmarkdown",
								Content: fmt.Sprintf("**账号**\n%s", maskedAccount),
							},
							{
								Type:    "kmarkdown",
								Content: fmt.Sprintf("**操作原因**\n%s", replaceGzs(record.GetString("action_reason"))),
							},
							{
								Type:    "kmarkdown",
								Content: fmt.Sprintf("**操作时长**\n%s", duration),
							},
						},
					},
				},

				// 被盗号风险提示板块
				{
					Type: "divider",
				},
				{
					Type: "section",
					Text: model.CardText{
						Type: "kmarkdown",
						Content: fmt.Sprintf("**账号安全风险检测**: %s\n%s",
							ternaryString(isHijackRisk, "⚠️ 高风险", "✅ 正常"),
							ternaryString(isHijackRisk,
								"检测到异常操作，建议立即修改密码并启用二次验证！",
								"账号安全状态正常")),
					},
				},

				// 第三部分: 带有 kmarkdown 的 context
				{
					Type: "context",
					Elements: []model.CardModule{
						{
							Type:    "kmarkdown",
							Content: "如有异议，请通过 [网站](https://cn.turtle-wow.org/) 提交申诉。\n请大家引以为戒，遵守游戏规则，营造健康的游戏环境",
						},
					},
				},
			}

			cardMessage := &model.CardMessageReq{
				&model.CardMessage{
					Type:    "card",
					Theme:   ternaryTheme(isHijackRisk, model.ThemeTypeDanger, model.ThemeTypePrimary),
					Size:    model.SizeLg,
					Modules: modules,
				},
			}

			// 使用 encoding/json 序列化
			cardMessageContent, err := json.Marshal(cardMessage)
			if err != nil {
				fmt.Println("Error serializing card message:", err)
				return err
			}

			// 创建 MessageCreateReq 请求
			req := &model.MessageCreateReq{
				Type:     10,            // 假设 10 代表卡片消息的类型，需根据实际 API 文档确认
				TargetId: koooktargetid, // 替换为实际的目标ID (例如频道ID或用户ID)
				Content:  string(cardMessageContent),
			}

			resp, err := action.MessageSend(req)
			if err != nil {
				log.Errorf("发送消息失败: %v", err)
			} else {
				log.Infof("成功发送消息: %v", resp)
			}

		}

		return nil
	})

	// 配置管理员账号(在启动前设置环境变量)
	adminEmail := "admin@yourdomain.com"  // 请替换为实际管理员邮箱
	adminPassword := "StrongPassword123!" // 请替换为强密码
	os.Setenv("PB_ADMIN_EMAIL", adminEmail)
	os.Setenv("PB_ADMIN_PASSWORD", adminPassword)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configure and start server
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start the security monitoring server",
		Run: func(cmd *cobra.Command, args []string) {
			// Set environment variables
			os.Setenv("PB_BIND", "0.0.0.0:8090")
			os.Setenv("PB_ADMIN_EMAIL", "admin@example.com")
			os.Setenv("PB_ADMIN_PASSWORD", "your-strong-password")

			// 如果启用debug模式，设置PocketBase开发模式
			debug, _ := cmd.Flags().GetBool("debug")
			if debug {
				os.Setenv("PB_DEV", "true")
				log.SetLevel(log.DebugLevel)
			}

			// 启动服务并打印详细日志
			log.Info("Starting PocketBase server...")
			if err := app.Start(); err != nil {
				log.WithError(err).Fatal("Failed to start PocketBase")
				return
			}
			log.Info("PocketBase server started successfully on :8090")

			// 服务启动后启动记录处理
			go addRecords(ctx, app, urls, username, password)
			return
		},
	}
	// 添加--debug flag
	serverCmd.Flags().Bool("debug", false, "Enable debug mode")

	log.Info("Adding server command to root command")
	app.RootCmd.AddCommand(serverCmd)

	log.Info("Starting command execution")
	if err := app.RootCmd.Execute(); err != nil {
		log.WithError(err).Fatal("Command execution failed")
	}

	select {
	case <-ctx.Done():
		log.Info("Context cancelled, shutting down")
	}

}

func addRecords(ctx context.Context, app *pocketbase.PocketBase, urls []string, username, password string) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var wg sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping record addition due to context cancellation")
			return
		case <-ticker.C:
			for _, url := range urls {
				wg.Add(1)
				go func(url string) {
					defer wg.Done()
					records, err := fetchCSV(url, username, password)
					if err != nil {
						log.WithError(err).Errorf("Error fetching CSV from %s", url)
						return
					}
					parseRecords(records, app, url)
				}(url)
			}
			wg.Wait()
		}
	}
}

type MyEventHandler struct {
	event.BaseEventHandler
}

// DoKMarkDown A simple Kook robot implementation that sends new messages back to the corresponding channel/private chat
func (h *MyEventHandler) DoKMarkDown(event *model.Event) {
	//	content := event.Content
	log.Infof("event:%v", event)
	log.Infof("TargetId:%v", event.TargetId)
	extra := event.GetUserExtra()
	if extra.Author.Bot {
		log.Warnf("Bot message, skip")
		return
	}

	/*
		req := &model.MessageCreateReq{
			Type:     1,
			Content:  "Repeat by kook bot:" + content,
			TargetId: event.TargetId,
		}
		action.MessageSend(req)
	*/
}

// fetchCSV 从指定URL获取CSV内容，并使用Basic Authorization进行认证

func fetchCSV(url, username, password string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// 设置Basic Authorization头部
	auth := username + ":" + password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Add("Authorization", "Basic "+encodedAuth)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// 检查HTTP响应状态码
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get content: %s", resp.Status)
	}

	// 检查Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/csv") && !strings.HasPrefix(contentType, "text/plain") {
		return "", fmt.Errorf("unexpected content type: %s", contentType)
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// 三目运算符辅助函数（专用于CardThemeType）
func ternaryTheme(condition bool, trueVal, falseVal model.CardThemeType) model.CardThemeType {
	if condition {
		return trueVal
	}
	return falseVal
}

// 三目运算符辅助函数（通用字符串）
func ternaryString(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

// 检测被盗号风险
func checkAccountHijackRisk(account string, timestamp string, ip string) bool {
	// 启动安全监控
	go StartTradeMonitor()

	// 简单检查IP是否异常
	if ip != "" && strings.HasPrefix(ip, "192.168.") {
		return false // 内网IP视为安全
	}

	// 检查是否有异常交易记录
	db, err := sql.Open("sqlite3", "./pb_data/data.db")
	if err != nil {
		log.Errorf("数据库连接失败: %v", err)
		return false
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM trade_records WHERE account = ? AND timestamp > datetime('now', '-1 hour')", account).Scan(&count)
	if err != nil {
		log.Errorf("查询失败: %v", err)
		return false
	}

	// 如果1小时内超过10笔交易视为高风险
	return count > 10
}

// parseRecords 解析CSV格式的字符串内容，并将结果录入Pocketbase数据库
func parseRecords(content string, app *pocketbase.PocketBase, url string) {

	collection, err := app.Dao().FindCollectionByNameOrId("gm_actions")
	if err != nil {
		log.Printf("无法找到表: %v", err)
		return
	}

	server := ""
	if strings.Contains(url, "dreamo") {
		server = "翡翠梦境"
	}

	if strings.Contains(url, "ringo") {
		server = "血环"
	}

	if strings.Contains(url, "hoggo") {
		server = "卡拉赞"
	}

	if strings.Contains(url, "ravo") {
		server = "拉文风暴"
	}

	// TrinityCore 日志正则表达式
	// 示例格式: [2025-06-01 12:34:56] GMLevel:3 Account:12345 Player:GMName Command:.additem 12345 1
	corePattern := `\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] GMLevel:(\d+) Account:(\d+) Player:(\S+) Command:(\.\S+)(.*)`

	// 敏感命令权重表
	commandWeights := map[string]int{
		".additem":       10, // 高风险
		".modify money":  10,
		".levelup":       8,
		".addspell":      8,
		".learn":         8,
		".cast":          8,
		".setskill":      8,
		".modify hp":     7,
		".modify mana":   7,
		".modify energy": 7,
		".appear":        6,
		".summon":        6,
		".modify rep":    5,
		".modify arena":  5,
		".npc add":       5,
		".creature add":  5,
		".unaura all":    4,
		".tele":          4, // 中风险
	}

	coreRegex := regexp.MustCompile(corePattern)

	lines := strings.Split(content, "\n")
	suspiciousRecords := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := coreRegex.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}

		timestamp := matches[1]
		gmLevel, _ := strconv.Atoi(matches[2])
		gmName := matches[4]
		command := matches[5]
		args := strings.TrimSpace(matches[6])

		// 只监控等级≥3的GM
		if gmLevel < 3 {
			continue
		}

		// 检查命令权重
		weight := 0
		for cmd, w := range commandWeights {
			if strings.HasPrefix(command, cmd) {
				weight = w
				break
			}
		}
		// 只监控权重≥4的命令
		if weight < 4 {
			continue
		}

		// 检查是否有工单关联
		hasTicket, ticketID := checkNearbyTicketCommand(lines, timestamp, gmName)

		// 如果是工单相关命令或包含工单ID，则允许
		if hasTicket || (command == ".summon" && strings.Contains(args, "ticket:")) ||
			(ticketID != "" && strings.Contains(args, ticketID)) {
			continue
		}

		// 初始化评分器
		scorer := NewGmBehaviorScorer()

		// 检查自操作
		isSelfOp := isSelfOperation(matches[3], args)

		// 记录可疑操作
		if !hasTicket || isSelfOp {
			shouldAlert := scorer.AddScore(matches[3], weight)
			suspiciousRecords = append(suspiciousRecords, line)

			// 高风险操作或累计评分触发告警
			if weight >= 8 || shouldAlert {
				log.Warnf("高风险GM操作 - %s: %s %s (风险等级:%d)",
					gmName, command, args, weight)
			} else {
				log.Infof("可疑GM操作 - %s: %s %s (风险等级:%d)",
					gmName, command, args, weight)
			}
		}

		md5Value := calculateMD5(line)

		// 检查是否已存在具有相同MD5的记录
		existingRecord, _ := app.Dao().FindFirstRecordByData("gm_actions", "md5", md5Value)

		if existingRecord != nil {
			log.Warnf("重复记录，跳过：: %s", command[1])
			continue // 跳过创建记录
		} else {

			record := models.NewRecord(collection)

			// 设置记录数据
			record.Set("date", timestamp)
			record.Set("gm_command", command+" "+args)
			record.Set("action_type", strings.TrimPrefix(command, "."))
			record.Set("player_acc", extractTargetAccount(args))
			record.Set("action_duration", extractDuration(args))
			record.Set("action_reason", extractReason(args))
			record.Set("gm_char", gmName)
			record.Set("gm_acc", matches[3])
			record.Set("risk_weight", weight)
			record.Set("md5", md5Value)
			record.Set("server", server)

			// 使用app.Dao()创建记录
			if err := app.Dao().SaveRecord(record); err != nil {
				log.Printf("错误创建记录: %v", err)
			} else {
				log.Printf("成功添加记录: %v", record.GetId())
			}
		}
	}
}

// calculateMD5 计算给定字符串的 MD5 值并返回十六进制字符串
func calculateMD5(value string) string {
	hash := md5.New()
	io.WriteString(hash, value)
	return hex.EncodeToString(hash.Sum(nil))
}

// MaskAccount 根据客户账号屏蔽一半字符
func MaskAccount(account string) (string, error) {
	// 转换为rune切片以处理UTF-8字符
	runes := []rune(account)
	length := len(runes)

	// 打印调试信息，检查输入长度
	log.Printf("Account: %s, Length: %d\n", account, length)

	// 确保账号长度至少3个字符
	if length < 3 {
		return "", fmt.Errorf("账号名至少需要3个字符")
	}

	// 计算需要屏蔽的字符数，屏蔽一半的字符
	maskCount := length / 2

	// 打印需要屏蔽的字符数
	log.Printf("Mask Count: %d\n", maskCount)

	// 创建屏蔽后的字符切片
	maskedRunes := make([]rune, length)

	// 前maskCount字符用*替换，后半部分保留原始字符
	for i := 0; i < length; i++ {
		if i < maskCount {
			maskedRunes[i] = '*'
		} else {
			maskedRunes[i] = runes[i]
		}

		// 打印每次迭代的结果
		log.Printf("Index: %d, Char: %c\n", i, maskedRunes[i])
	}

	return string(maskedRunes), nil
}

func parseTime(input string) (string, error) {
	// 定义正则表达式模式
	timePattern := regexp.MustCompile(`(?i)(-1|(\d+)([dhm]))`)

	// 匹配输入字符串
	matches := timePattern.FindStringSubmatch(input)
	if matches == nil {
		return "", fmt.Errorf("无效的时间格式")
	}

	// 提取匹配的内容
	unit := strings.ToLower(matches[3]) // 获取时间单位并统一为小写
	value := matches[2]                 // 获取时间值

	// 判断是否是永久(-1)
	if matches[1] == "-1" {
		return "永久", nil
	}

	// 将字符串转换为整数
	num, err := strconv.Atoi(value)
	if err != nil {
		return "", err
	}

	// 根据时间单位返回相应的描述
	switch unit {
	case "d":
		return fmt.Sprintf("%d天", num), nil
	case "h":
		return fmt.Sprintf("%d小时", num), nil
	case "m":
		return fmt.Sprintf("%d分钟", num), nil
	}

	return "", fmt.Errorf("未知的时间单位")
}

func replaceGzs(input string) string {
	// 将输入字符串转换为小写以便进行不区分大小写的比较
	lowerInput := strings.ToLower(input)

	// 如果包含 "gzs"，则进行替换
	if strings.Contains(lowerInput, "gzs") {
		return strings.ReplaceAll(lowerInput, "gzs", "其他违规")
	}

	return strings.ReplaceAll(input, "GZS", "其他违规")
}
