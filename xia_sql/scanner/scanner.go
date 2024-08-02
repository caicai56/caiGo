package scanner

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"xia_sql/vars"
)

func DetectSQLInjection(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("解析URL失败: %v", err)
	}

	paramName := ""
	queryParams := u.Query()
	for key := range queryParams {
		paramName = key
		break
	}

	if paramName == "" {
		return fmt.Errorf("URL中未找到查询参数")
	}

	startTime := time.Now()
	respNormal, err := http.Get(baseURL)
	if err != nil {
		return fmt.Errorf("普通请求失败: %v", err)
	}
	normalBody, err := ioutil.ReadAll(respNormal.Body)
	if err != nil {
		return fmt.Errorf("读取普通响应体失败: %v", err)
	}
	respNormal.Body.Close()
	normalDuration := time.Since(startTime)

	fmt.Printf("普通请求耗时: %v\n", normalDuration)

	for _, payload := range vars.Payloads {
		q := u.Query()
		q.Set(paramName, payload)
		u.RawQuery = q.Encode()
		payloadURL := u.String()

		startTime := time.Now()
		respPayload, err := http.Get(payloadURL)
		if err != nil {
			return fmt.Errorf("使用payload '%s' 发起请求失败: %v", payload, err)
		}
		payloadBody, err := ioutil.ReadAll(respPayload.Body)
		if err != nil {
			return fmt.Errorf("读取带payload '%s' 的响应体失败: %v", payload, err)
		}
		respPayload.Body.Close()
		payloadDuration := time.Since(startTime)

		fmt.Printf("payload '%s' 请求耗时: %v\n", payload, payloadDuration)

		if payloadDuration > 3*time.Second {
			return fmt.Errorf("耗时 > 3秒: 可能存在基于时间的SQL注入，payload为 '%s'", payload)
		}

		if containsError(payloadBody) {
			return fmt.Errorf("错误: 在响应中检测到数据库错误，payload为 '%s'", payload)
		}

		if isInjectionPossible(normalBody, payloadBody) {
			fmt.Printf("✔️ ==> ? : 可能存在SQL注入，payload为 '%s'\n", payload)
		}

		if strings.Contains(string(payloadBody), "error") {
			return fmt.Errorf("错误: 在响应中检测到SQL错误，payload为 '%s'", payload)
		}

		if strings.Contains(string(payloadBody), "success") || strings.Contains(string(payloadBody), "failed") {
			return fmt.Errorf("错误: 在响应中检测到敏感信息，payload为 '%s'", payload)
		}

		if payloadDuration > normalDuration+time.Millisecond*100 {
			return fmt.Errorf("错误: 在响应中检测到时间延迟，payload为 '%s'", payload)
		}
	}

	return nil
}

func containsError(body []byte) bool {
	return strings.Contains(string(body), "error")
}

func isInjectionPossible(normalBody, payloadBody []byte) bool {
	normalLength := len(normalBody)
	payloadLength := len(payloadBody)

	if payloadLength != normalLength {
		return true
	}

	singleQuote := `'`
	doubleQuote := "''"
	replacedPayloadBody := strings.ReplaceAll(string(payloadBody), doubleQuote, singleQuote)
	if len(replacedPayloadBody) != normalLength {
		return true
	}

	return false
}
