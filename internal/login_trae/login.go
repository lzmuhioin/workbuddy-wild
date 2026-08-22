// Package login_trae 实现 TraeWork OAuth 回调登录。
package login_trae

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/rockswang/workbuddy-wild/internal/auth"
	"github.com/rockswang/workbuddy-wild/internal/traework"
)

var ErrPending = errors.New("login pending")

type Result struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
	Domain       string
	ApiHost      string
	MachineID    string
	DeviceID     string
	UID          string
	EnterpriseID string
	Nickname     string
}

type state struct {
	MachineID    string `json:"machineId"`
	DeviceID     string `json:"deviceId"`
	RefreshToken string `json:"refreshToken,omitempty"`
	Host         string `json:"host,omitempty"`
	Err          string `json:"err,omitempty"`
}

func NewClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

var netConfigPat = regexp.MustCompile(`device_id&#\*([^@$]+)@\$\*`)

// realDeviceID 尽力读取本机未打开的官方 Trae 客户端注册的设备 ID。
//
// Trae SOLO CN 签到接口 (api.trae.cn/trae/api/v2/ug/checkin_credits/claim) 会校验
// `x-device-id` 是否为账号绑定的真实设备: 用随机值会被风控返回 code=9074
// 「当前参与用户太多，请稍后再试」。官方客户端把注册设备 ID 存在
// `tt_net_config.config` 的 `device_id&#*<id>@$*` 字段里 (Windows:
// %APPDATA%\TRAE SOLO CN\ahanet	t_net_config.config)。
// 读不到时返回空串, 由调用方回退到随机值。
func realDeviceID() string {
	var cfgPath string
	switch runtime.GOOS {
	case "windows":
		cfgPath = filepath.Join(os.Getenv("APPDATA"), "TRAE SOLO CN", "ahanet", "tt_net_config.config")
	case "darwin":
		home, _ := os.UserHomeDir()
		cfgPath = filepath.Join(home, "Library", "Application Support", "TRAE SOLO CN", "ahanet", "tt_net_config.config")
	default: // linux 等
		home, _ := os.UserHomeDir()
		cfgPath = filepath.Join(home, ".config", "TRAE SOLO CN", "ahanet", "tt_net_config.config")
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	m := netConfigPat.FindSubmatch(raw)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// Start 启动本地一次性回调监听，返回 Trae 授权 URL。
func Start(client *http.Client, statePath string) (string, error) {
	// 优先复用本机官方 Trae 客户端的真实设备 ID, 避免签到被 9074 风控; 读不到才随机生成。
	machineID := randHex(16)
	deviceID := realDeviceID()
	if deviceID == "" {
		deviceID = randHex(16)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	callback := "http://" + addr + "/authorize"
	st := state{MachineID: machineID, DeviceID: deviceID}
	if err := writeState(statePath, st); err != nil {
		_ = ln.Close()
		return "", err
	}

	srv := &http.Server{ReadHeaderTimeout: 15 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		st.RefreshToken = q.Get("refreshToken")
		st.Host = q.Get("host")
		if st.Host == "" {
			st.Host = traework.OAuthHost
		}
		if st.RefreshToken == "" {
			st.Err = "missing refreshToken in callback"
		}
		_ = writeState(statePath, st)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body style='font-family:sans-serif;padding:24px'>TraeWork 登录已完成，可以关闭此页面。</body></html>"))
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	})
	go func() { _ = srv.Serve(ln) }()
	go func() {
		time.Sleep(5 * time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	u, _ := url.Parse(traework.ConsoleHost + "/authorization")
	v := u.Query()
	v.Set("login_version", "1")
	v.Set("auth_from", "solo")
	v.Set("login_channel", "native_ide")
	v.Set("plugin_version", "2.3.62834")
	v.Set("auth_type", "local")
	v.Set("client_id", traework.ClientID)
	v.Set("redirect", "0")
	v.Set("login_trace_id", randHex(8))
	v.Set("auth_callback_url", callback)
	v.Set("machine_id", machineID)
	v.Set("device_id", deviceID)
	v.Set("x_device_id", deviceID)
	v.Set("x_machine_id", machineID)
	v.Set("x_device_brand", "PC")
	v.Set("x_device_type", "PC")
	v.Set("x_os_version", "1.0")
	v.Set("x_app_version", traework.IdeVersion)
	v.Set("x_app_type", "stable")
	u.RawQuery = v.Encode()
	_ = client
	return u.String(), nil
}

// Poll 检查回调是否已写入 state，完成后 ExchangeToken + GetUserInfo。
func Poll(client *http.Client, statePath string) (Result, error) {
	var st state
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return Result{}, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return Result{}, err
	}
	if st.Err != "" {
		return Result{}, errors.New(st.Err)
	}
	if st.RefreshToken == "" {
		return Result{}, ErrPending
	}
	if st.Host == "" {
		st.Host = traework.OAuthHost
	}
	c := traework.New()
	c.HTTP = client
	a := &auth.Auth{Kind: "traework", RefreshToken: st.RefreshToken, ApiHost: st.Host, MachineID: st.MachineID, DeviceID: st.DeviceID, Domain: "trae.cn"}
	if err := c.RefreshToken(a); err != nil {
		return Result{}, err
	}
	uid, nick, ent, err := c.GetUserInfo(a)
	if err != nil {
		return Result{}, err
	}
	_ = os.Remove(statePath)
	return Result{AccessToken: a.AccessToken, RefreshToken: a.RefreshToken, ExpiresAt: a.ExpiresAt, Domain: "trae.cn", ApiHost: st.Host, MachineID: st.MachineID, DeviceID: st.DeviceID, UID: uid, EnterpriseID: ent, Nickname: nick}, nil
}

func SaveAuth(authDir string, r Result) (string, error) {
	if r.UID == "" {
		return "", fmt.Errorf("missing uid in result")
	}
	doc := map[string]any{
		"auth":    map[string]any{"accessToken": r.AccessToken, "refreshToken": r.RefreshToken, "expiresAt": r.ExpiresAt, "domain": r.Domain, "apiHost": r.ApiHost, "machineId": r.MachineID, "deviceId": r.DeviceID},
		"account": map[string]any{"uid": r.UID, "enterpriseId": r.EnterpriseID, "nickname": r.Nickname},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	_ = os.MkdirAll(authDir, 0o755)
	fp := filepath.Join(authDir, "trae-"+r.UID+".json")
	tmp := fp + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, fp); err != nil {
		return "", err
	}
	return fp, nil
}

func writeState(path string, st state) error {
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	raw, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(path, raw, 0o600)
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }
