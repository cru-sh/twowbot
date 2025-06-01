package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// 从命令参数中提取目标账号
func extractTargetAccount(args string) string {
	// 尝试匹配账号ID格式
	re := regexp.MustCompile(`(\d{5,})`)
	if matches := re.FindStringSubmatch(args); len(matches) > 0 {
		return matches[1]
	}

	// 尝试匹配角色名格式
	re = regexp.MustCompile(`"([^"]+)"`)
	if matches := re.FindStringSubmatch(args); len(matches) > 0 {
		return matches[1]
	}

	return "未知目标"
}

// 检查是否是自操作
func isSelfOperation(gmAccount string, args string) bool {
	targetAccount := extractTargetAccount(args)
	return targetAccount == gmAccount
}

// GM行为评分器
type GmBehaviorScorer struct {
	scores map[string]int // gmAccount -> score
	mu     sync.Mutex
}

func NewGmBehaviorScorer() *GmBehaviorScorer {
	return &GmBehaviorScorer{
		scores: make(map[string]int),
	}
}

func (s *GmBehaviorScorer) AddScore(gmAccount string, weight int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scores[gmAccount] += weight
	if s.scores[gmAccount] >= 30 {
		s.scores[gmAccount] = 0
		return true
	}
	return false
}

func (s *GmBehaviorScorer) Cleanup() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		s.mu.Lock()
		for k := range s.scores {
			delete(s.scores, k)
		}
		s.mu.Unlock()
	}
}

// 从命令参数中提取操作时长
func extractDuration(args string) string {
	// 匹配时长格式如"2d"、"3h"、"30m"
	re := regexp.MustCompile(`(\d+[dhm])`)
	if matches := re.FindStringSubmatch(args); len(matches) > 0 {
		return matches[1]
	}

	// 匹配永久标记
	if strings.Contains(args, "perm") || strings.Contains(args, "-1") {
		return "perm"
	}

	return "未知时长"
}

// 从命令参数中提取操作原因
func extractReason(args string) string {
	// 匹配引号内的原因
	re := regexp.MustCompile(`"([^"]+)"`)
	if matches := re.FindAllStringSubmatch(args, -1); len(matches) > 1 {
		return matches[1][1]
	}

	// 匹配原因关键字
	keywords := []string{"reason:", "原因:", "for "}
	for _, kw := range keywords {
		if idx := strings.Index(args, kw); idx != -1 {
			return strings.TrimSpace(args[idx+len(kw):])
		}
	}

	return "未说明原因"
}

// 检查附近是否有工单命令（增强版）
func checkNearbyTicketCommand(lines []string, timestamp string, gmName string) (bool, string) {
	cmdTime, err := time.Parse("2006-01-02 15:04:05", timestamp)
	if err != nil {
		return false, ""
	}

	// 工单ID正则
	ticketIDRe := regexp.MustCompile(`ticket (\d+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 检查是否是同一个GM的命令
		if !strings.Contains(line, "Player:"+gmName) {
			continue
		}

		// 提取时间
		start := strings.Index(line, "[") + 1
		end := strings.Index(line, "]")
		if start < 0 || end < 0 {
			continue
		}
		lineTime, err := time.Parse("2006-01-02 15:04:05", line[start:end])
		if err != nil {
			continue
		}

		// 检查时间范围(±5分钟)
		if lineTime.After(cmdTime.Add(-5*time.Minute)) &&
			lineTime.Before(cmdTime.Add(5*time.Minute)) {

			// 检查工单相关命令
			if strings.Contains(line, "Command:.ticket") ||
				strings.Contains(line, "Command:.help") ||
				strings.Contains(line, "Command: send mail") ||
				strings.Contains(line, "Command: ticket close") {

				// 尝试提取工单ID
				if matches := ticketIDRe.FindStringSubmatch(line); len(matches) > 0 {
					return true, matches[1]
				}
				return true, ""
			}
		}
	}
	return false, ""
}
