package checker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CheckResult 检查结果
type CheckResult struct {
	Name    string // nmap / nuclei
	Found   bool
	Path    string
	Version string
	Error   string
}

// CheckNmap 检查 nmap 是否可用
func CheckNmap(nmapPath string) CheckResult {
	result := CheckResult{Name: "nmap"}

	path, err := exec.LookPath(nmapPath)
	if err != nil {
		result.Error = fmt.Sprintf("nmap 未找到 (%s)，端口扫描将使用 Go 原生 TCP 扫描（功能受限）", nmapPath)
		return result
	}

	result.Found = true
	result.Path = path

	// 获取版本
	out, err := exec.Command(path, "--version").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			result.Version = strings.TrimSpace(lines[0])
		}
	}

	return result
}

// CheckNuclei 检查 nuclei 是否可用
func CheckNuclei(nucleiPath string) CheckResult {
	result := CheckResult{Name: "nuclei"}

	path, err := exec.LookPath(nucleiPath)
	if err != nil {
		result.Error = fmt.Sprintf("nuclei 未找到 (%s)，漏洞扫描将无法执行", nucleiPath)
		return result
	}

	result.Found = true
	result.Path = path

	// 获取版本
	out, err := exec.Command(path, "-version").Output()
	if err == nil {
		result.Version = strings.TrimSpace(string(out))
	}

	return result
}

// InstallDir 获取安装目录（项目目录下的 tools）
func InstallDir() string {
	// 获取可执行文件所在目录
	exePath, err := os.Executable()
	if err != nil {
		dir := filepath.Join(os.Getenv("USERPROFILE"), ".vulnscope", "tools")
		os.MkdirAll(dir, 0755)
		return dir
	}
	dir := filepath.Join(filepath.Dir(exePath), "tools")
	os.MkdirAll(dir, 0755)
	return dir
}

// DownloadNuclei 下载 nuclei
func DownloadNuclei() (string, error) {
	installDir := InstallDir()
	exeName := "nuclei"
	if runtime.GOOS == "windows" {
		exeName = "nuclei.exe"
	}
	targetPath := filepath.Join(installDir, exeName)

	// 如果已存在，直接返回
	if _, err := os.Stat(targetPath); err == nil {
		return targetPath, nil
	}

	// 确定 GitHub release 下载 URL
	goos := runtime.GOOS
	arch := runtime.GOARCH
	// nuclei v3 release 文件名格式: nuclei_{version}_{goos}_{arch}.zip
	// 需要先查询最新版本号

	// 直接使用 GOARCH，nuclei 支持 amd64/arm64/386
	// 不做映射，保持原值

	// 查询最新版本号
	version, err := getLatestNucleiVersion()
	if err != nil {
		return "", fmt.Errorf("查询 nuclei 最新版本失败: %v\n请手动下载: https://github.com/projectdiscovery/nuclei/releases", err)
	}
	log.Printf("[Checker] nuclei 最新版本: %s\n", version)

	// nuclei v3 的 release 文件名格式: nuclei_{version}_{goos}_{arch}.zip
	// 例如: nuclei_3.8.0_linux_amd64.zip
	zipName := fmt.Sprintf("nuclei_%s_%s_%s.zip", version, goos, arch)
	url := fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/download/v%s/%s", version, zipName)

	log.Printf("[Checker] 正在下载 nuclei: %s\n", url)

	zipPath := filepath.Join(installDir, zipName)
	hash, err := downloadFile(url, zipPath)
	if err != nil {
		return "", fmt.Errorf("下载 nuclei 失败: %v\n请手动下载: https://github.com/projectdiscovery/nuclei/releases", err)
	}
	log.Printf("[Checker] nuclei 下载完成, SHA256: %s\n", hash)

	// 解压
	log.Println("[Checker] 正在解压 nuclei...")
	if runtime.GOOS == "windows" {
		if err := exec.Command("powershell", "-Command",
			fmt.Sprintf("Expand-Archive -Path '%s' -DestinationPath '%s' -Force", zipPath, installDir)).Run(); err != nil {
			return "", fmt.Errorf("解压失败: %v", err)
		}
	} else {
		if err := exec.Command("unzip", "-o", zipPath, "-d", installDir).Run(); err != nil {
			return "", fmt.Errorf("解压失败: %v (请安装 unzip)", err)
		}
	}

	// 清理 zip
	os.Remove(zipPath)

	// Linux/macOS 设置可执行权限
	if runtime.GOOS != "windows" {
		os.Chmod(targetPath, 0755)
	}

	// 验证
	if _, err := os.Stat(targetPath); err != nil {
		// 尝试在子目录中查找
		filepath.Walk(installDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.Name() == exeName {
				os.Rename(path, targetPath)
				return filepath.SkipAll
			}
			return nil
		})
	}

	if _, err := os.Stat(targetPath); err != nil {
		return "", fmt.Errorf("nuclei 安装失败，请手动下载: https://github.com/projectdiscovery/nuclei/releases")
	}

	// 校验下载文件的 SHA256（对解压后的可执行文件）
	exeHash, err := fileSHA256(targetPath)
	if err == nil {
		log.Printf("[Checker] nuclei 可执行文件 SHA256: %s（请与官方校验值比对）\n", exeHash)
	}

	log.Printf("[Checker] nuclei 安装成功: %s\n", targetPath)
	return targetPath, nil
}

// DownloadNmap 下载 nmap (Windows)
func DownloadNmap() (string, error) {
	installDir := InstallDir()
	nmapDir := filepath.Join(installDir, "nmap")
	targetPath := filepath.Join(nmapDir, "nmap.exe")

	// 如果已存在，直接返回
	if _, err := os.Stat(targetPath); err == nil {
		return targetPath, nil
	}

	// nmap Windows 安装包
	url := "https://nmap.org/dist/nmap-7.99-setup.exe"
	installerPath := filepath.Join(installDir, "nmap-setup.exe")

	log.Printf("[Checker] 正在下载 nmap 安装包: %s\n", url)

	hash, err := downloadFile(url, installerPath)
	if err != nil {
		return "", fmt.Errorf("下载 nmap 失败: %v\n请手动下载: https://nmap.org/download.html", err)
	}
	log.Printf("[Checker] nmap 下载完成, SHA256: %s（请与官方校验值比对）\n", hash)

	// 静默安装
	fmt.Println("[Checker] 正在安装 nmap（静默安装）...")
	cmd := exec.Command(installerPath, "/S", fmt.Sprintf("/D=%s", nmapDir))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("nmap 安装失败: %v\n请手动安装: https://nmap.org/download.html", err)
	}

	// 清理安装包
	os.Remove(installerPath)

	// 验证
	if _, err := os.Stat(targetPath); err != nil {
		return "", fmt.Errorf("nmap 安装失败，请手动安装: https://nmap.org/download.html")
	}

	log.Printf("[Checker] nmap 安装成功: %s\n", targetPath)
	return targetPath, nil
}

// CheckAndInstall 检查并自动安装缺失的工具
// 返回 nmapPath, nucleiPath, warnings
func CheckAndInstall(nmapPath, nucleiPath string) (string, string, []string) {
	var warnings []string

	// 检查 nmap
	nmapResult := CheckNmap(nmapPath)
	if !nmapResult.Found {
		log.Println("[Checker] nmap 未安装，正在尝试自动下载...")
		path, err := DownloadNmap()
		if err != nil {
			warnings = append(warnings, err.Error())
			log.Printf("[Checker] nmap 自动安装失败: %v\n", err)
			log.Println("[Checker] 端口扫描将使用 Go 原生 TCP 扫描（仅支持常见端口）")
		} else {
			nmapPath = path
			log.Printf("[Checker] nmap 已安装: %s\n", path)
		}
	} else {
		log.Printf("[Checker] nmap 已就绪: %s %s\n", nmapResult.Path, nmapResult.Version)
	}

	// 检查 nuclei
	nucleiResult := CheckNuclei(nucleiPath)
	if !nucleiResult.Found {
		log.Println("[Checker] nuclei 未安装，正在尝试自动下载...")
		path, err := DownloadNuclei()
		if err != nil {
			warnings = append(warnings, err.Error())
			log.Printf("[Checker] nuclei 自动安装失败: %v\n", err)
		} else {
			nucleiPath = path
			log.Printf("[Checker] nuclei 已安装: %s\n", path)
		}
	} else {
		log.Printf("[Checker] nuclei 已就绪: %s %s\n", nucleiResult.Path, nucleiResult.Version)
	}

	return nmapPath, nucleiPath, warnings
}

// getLatestNucleiVersion 通过 GitHub API 查询 nuclei 最新版本号
func getLatestNucleiVersion() (string, error) {
	url := "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求 GitHub API 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API 返回状态码: %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("解析 GitHub API 响应失败: %v", err)
	}

	// tag_name 格式为 "v3.8.0"，去掉 "v" 前缀
	version := strings.TrimPrefix(release.TagName, "v")
	return version, nil
}

func downloadFile(url, filePath string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// 边下载边计算 SHA256
	hasher := sha256.New()
	counter := &writeCounter{}
	_, err = io.Copy(f, io.TeeReader(io.TeeReader(resp.Body, hasher), counter))
	fmt.Println() // 换行
	if err != nil {
		return "", err
	}

	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash, nil
}

// fileSHA256 计算文件的 SHA256 哈希值
func fileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type writeCounter struct {
	Total uint64
}

func (wc *writeCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc *writeCounter) PrintProgress() {
	fmt.Fprintf(os.Stderr, "\r[Checker] 下载中... %d MB", wc.Total/1024/1024)
}
