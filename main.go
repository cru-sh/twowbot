package main

import (
	"context"
	"crypto/md5"
	"io"
	"os"
	"strconv"
	"time"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
	log "github.com/sirupsen/logrus"

	"github.com/aimerny/kook-go/app/common"
	"github.com/aimerny/kook-go/app/core/action"
	"github.com/aimerny/kook-go/app/core/event"
	"github.com/aimerny/kook-go/app/core/model"
	"github.com/aimerny/kook-go/app/core/session"
)

func main() {

	urls := []string{
		//	"https://dreamo.happydoghouse.link/query?f=gm.log&q=ban%20acc&l=1000",
		"https://ringo.happydoghouse.link/query?f=gm.log&q=ban%20acc&l=1000",
		"https://hoggo.happydoghouse.link/query?f=gm.log&q=ban%20acc&l=1000",
		"https://ravo.happydoghouse.link/query?f=gm.log&q=ban%20acc&l=1000",
		// 添加更多 URL
	}

	username := "k8ok8o"
	password := "C9GS5UUzFqmmDQH8NEUP"

	// 测试机器人
	//kooktoken := "1/MjM0OTY=/PqEFBx0mZWWFOUmmv5crWw=="

	//TWOW-GMBOT
	kooktoken := "1/MjM2ODQ=/23fcJkT0ecZz+pr3SnIqYQ=="

	//测试渠道
	//koooktargetid := "2542015504189926"

	//播报频道
	koooktargetid := "5925968108780607"

	//C/GM管理频道
	//koooktargetid := "9225622321653596"

	//Bot
	common.InitLogger()

	globalSession, err := session.CreateSession(kooktoken, true)
	if err != nil {
		log.Errorf("%s", err)
	}
	globalSession.RegisterEventHandler(&MyEventHandler{})
	go globalSession.Start()

	//pocketbase
	app := pocketbase.New()

	// serves static files from the provided public dir (if exists)
	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS("./pb_public"), false))
		return nil
	})

	// 当gm_ban创建条目触发
	app.OnModelAfterCreate("gm_ban").Add(func(e *core.ModelEvent) error {
		log.Println(e.Model.TableName())
		log.Println(e.Model.GetId())

		// Cast the model to a Record to access its data map
		if record, ok := e.Model.(*models.Record); ok {

			log.Println("Data:", record.GetString("ban_command"))

			/*
				message := fmt.Sprintf("服务器： %s 账号： %s 被GM： %s 封禁 %s 原因 %s\n", record.GetString("server"), record.GetString("player_acc"), record.GetString("gm_char"), record.GetString("ban_dur"), record.GetString("ban_note"))

				req := &model.MessageCreateReq{
					Type:     9,
					Content:  message,
					TargetId: koooktargetid, // 替换为你要发送消息的目标ID
				}
			*/

			// 从 record 中获取 account 账号名

			maskedAccount, err := MaskAccount(record.GetString("player_acc"))

			duration, err := parseTime(record.GetString("ban_dur"))

			cardMessage := &model.CardMessageReq{
				&model.CardMessage{
					Type:  "card",
					Theme: model.ThemeTypeDanger,
					Size:  model.SizeLg,
					Modules: []model.CardModule{
						// 第一部分: 带有 kmarkdown 的 section
						*model.NewKMarkdown(fmt.Sprintf("**(font)[%s](font)[purple]封禁公告:**\n", record.GetString("server"))),

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
										Content: fmt.Sprintf("**封禁原因**\n%s", replaceGzs(record.GetString("ban_note"))),
									},
									{
										Type:    "kmarkdown",
										Content: fmt.Sprintf("**封禁时长**\n%s", duration),
									},
								},
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
					},
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

	// Start PocketBase in a separate goroutine
	go func() {
		if err := app.Start(); err != nil {
			log.Fatal(err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go addRecords(ctx, app, urls, username, password)

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

// parseRecords 解析CSV格式的字符串内容，并将结果录入Pocketbase数据库
func parseRecords(content string, app *pocketbase.PocketBase, url string) {

	collection, err := app.Dao().FindCollectionByNameOrId("gm_ban")
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

	// 正则表达式模式
	dateTimePattern := `^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`
	commandPattern := `Command: (ban account \S+ \S+ [^\[]+)`
	//accountPattern := `ban account (\S+) (\S+) ([^\[]+)`
	accountPattern := `ban account ('([^']+)'|(\S+)) (\S+) ('([^']+)'|([^' ]+))`

	playerPattern := `\[Player: (\S+) \(.*Account: (\d+)\)`

	dateTimeRegex := regexp.MustCompile(dateTimePattern)
	commandRegex := regexp.MustCompile(commandPattern)
	accountRegex := regexp.MustCompile(accountPattern)
	playerRegex := regexp.MustCompile(playerPattern)

	// 将内容按行分割
	lines := strings.Split(content, "\n")

	// 解析每行记录
	for _, line := range lines {
		line = strings.TrimSpace(line) // 去除首尾空白

		if line == "" {
			continue // 跳过空行
		}

		// 提取日期和时间
		dateTime := dateTimeRegex.FindStringSubmatch(line)
		if len(dateTime) == 0 {
			log.Println("DateTime 没找到，在行:", line)
			continue
		}

		// 提取完整的命令
		command := commandRegex.FindStringSubmatch(line)
		if len(command) == 0 {
			log.Println("Command 没找到，在行:", line)
			continue
		}

		// 提取账号、封禁时长和备注
		accountDetails := accountRegex.FindStringSubmatch(line)
		if len(accountDetails) == 0 {
			log.Println("Account 没找到，在行:", line)
			continue
		}

		// 处理提取到的账号、封禁时长和备注
		var account, banDuration, reason string
		if accountDetails[2] != "" {
			account = accountDetails[2] // 被单引号包围的账号
		} else {
			account = accountDetails[3] // 无单引号的账号
		}
		banDuration = accountDetails[4] // 封禁时长
		if accountDetails[6] != "" {
			reason = accountDetails[6] // 被单引号包围的备注
		} else {
			reason = accountDetails[7] // 无单引号的备注
		}

		// 提取GM名称和账号
		playerDetails := playerRegex.FindStringSubmatch(line)
		if len(playerDetails) == 0 {
			log.Println("Player 没找到，在行:", line)
			continue
		}

		md5Value := calculateMD5(command[1])

		// 检查是否已存在具有相同MD5的记录
		existingRecord, _ := app.Dao().FindFirstRecordByData("gm_ban", "md5", md5Value)

		if existingRecord != nil {
			log.Warnf("重复记录，跳过：: %s", command[1])
			continue // 跳过创建记录
		} else {

			record := models.NewRecord(collection)

			// 设置记录数据
			record.Set("date", dateTime[1])
			record.Set("ban_command", command[1])
			record.Set("player_acc", account)
			record.Set("ban_dur", banDuration)
			record.Set("ban_note", reason)
			record.Set("gm_char", playerDetails[1])
			record.Set("gm_acc", playerDetails[2])
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
