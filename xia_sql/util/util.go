package util

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/urfave/cli"
	"net/url"
	"os"
	"strings"
	"xia_sql/scanner"
	"xia_sql/vars"
)

// 检测网站是不是指向静态文件
func isStaticFile(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := u.Path
	staticDirs := []string{"/static/", "/assets/", "/public/"}
	for _, dir := range staticDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	staticExtensions := []string{".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".txt", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
	filename := path[strings.LastIndex(path, "/")+1:] 
	ext := strings.ToLower(strings.TrimPrefix(filename, "."))
	for _, extn := range staticExtensions {
		if ext == extn {
			return true
		}
	}

	return false
}

// 对url以及请求方式进行md5加密
func encodeAndHash(rawURL, method string) {

	encodedURL := url.QueryEscape(rawURL)

	input := encodedURL + method

	hash := md5.Sum([]byte(input))
	hashStr := hex.EncodeToString(hash[:])

	vars.HashesMux.Lock()
	vars.Hashes[hashStr] = struct{}{}
	vars.HashesMux.Unlock()
}

// 判断是不是之前已经重复请求过
func isHashExists(rawURL, method string) bool {

	encodedURL := url.QueryEscape(rawURL)
	input := encodedURL + method
	hash := md5.Sum([]byte(input))
	hashStr := hex.EncodeToString(hash[:])

	encodeAndHash(rawURL, method)

	vars.HashesMux.Lock()
	defer vars.HashesMux.Unlock()
	_, exists := vars.Hashes[hashStr]
	return exists
}

// 检测是不是在白名单里面
func CheckWhiteList(url string) bool {
	NewUrl, err := StripURLParams(url)
	if err != nil {
		fmt.Println(err)
		return false
	}
	for _, domain := range vars.WhiteSection {
		if strings.EqualFold(NewUrl, domain) {
			return true
		}

	}
	return false

}

// 解析url，返回不带参数的域名
func StripURLParams(rawURL string) (string, error) {

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	return parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path, nil
}

// 如果传入的是一个文件里面写了很多url，读文件里面的url
func ReadWhiteListFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line != "" {
			vars.UrlSection = append(vars.UrlSection, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return vars.UrlSection, nil
}

// 程序入口函数
func Scan(ctx *cli.Context) error {
	fmt.Println(123)
	if ctx.IsSet("url") {
		vars.Url = ctx.String("url")
	}
	if ctx.IsSet("whitelist") {
		wlist := ctx.String("whitelist")
		WhiteTemp := strings.Split(wlist, ",")
		for _, rawURL := range WhiteTemp {

			strippedURL, err := StripURLParams(rawURL)
			if err != nil {
				fmt.Printf("Error stripping URL params for %s: %v\n", rawURL, err)
				continue 
			}

			vars.WhiteSection = append(vars.WhiteSection, strippedURL)
		}
	}
	if ctx.IsSet("mode") {
		vars.Mode = ctx.String("mode")
	}
	if ctx.IsSet("file") {
		filename := ctx.String("file")
		WhiteSection, err := ReadWhiteListFromFile(filename)
		if err != nil {
			return err
		}
		vars.UrlSection = WhiteSection
	} else if ctx.IsSet("whitelist") {
		wlist := ctx.String("whitelist")
		vars.UrlSection = strings.Split(wlist, ",")
	}
	if ctx.IsSet("payloads") {
		paystr := ctx.String("payload")
		PayloadS := strings.Split(paystr, ",")
		vars.Payloads = append(vars.Payloads, PayloadS...)
	}
	if CheckWhiteList(vars.Url) || isHashExists(vars.Url, vars.Mode) || isStaticFile(vars.Url) {
		fmt.Println("此链接可能为白名单里面或者为静态文件或者已经被请求过")
	} else {
		err := scanner.DetectSQLInjection(vars.Url)
		if err != nil {
			fmt.Printf("Error during SQL injection detection: %v\n", err)
		}
	}
	return nil
}
