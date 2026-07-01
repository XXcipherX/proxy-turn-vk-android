package main

import (
	"encoding/json"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Profile holds consistent browser fingerprint headers for TLS+HTTP requests.
type Profile struct {
	UserAgent       string `json:"user_agent"`
	SecChUa         string `json:"sec_ch_ua"`
	SecChUaMobile   string `json:"sec_ch_ua_mobile"`
	SecChUaPlatform string `json:"sec_ch_ua_platform"`
}

// SavedProfile is a saved real browser profile loaded from disk.
type SavedProfile struct {
	Profile
	DeviceJSON string `json:"device_json"`
	Device     string `json:"device"`
	BrowserFp  string `json:"browser_fp"`
	CapturedAt float64 `json:"captured_at"`
}

const profileFile = "vk_profile.json"

func LoadProfileFromDisk() (*SavedProfile, error) {
	data, err := os.ReadFile(profileFile)
	if err != nil {
		return nil, err
	}
	var sp SavedProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, err
	}
	sp.Normalize()
	return &sp, nil
}

func (sp *SavedProfile) Normalize() {
	if sp == nil {
		return
	}
	sp.UserAgent = strings.TrimSpace(sp.UserAgent)
	sp.SecChUa = strings.TrimSpace(sp.SecChUa)
	sp.SecChUaMobile = strings.TrimSpace(sp.SecChUaMobile)
	sp.SecChUaPlatform = strings.TrimSpace(sp.SecChUaPlatform)
	sp.DeviceJSON = strings.TrimSpace(sp.DeviceJSON)
	sp.Device = strings.TrimSpace(sp.Device)
	sp.BrowserFp = strings.TrimSpace(decodeMaybeFormValue(sp.BrowserFp))

	if sp.DeviceJSON == "" && sp.Device != "" {
		sp.DeviceJSON = decodeMaybeFormValue(sp.Device)
	} else {
		sp.DeviceJSON = decodeMaybeFormValue(sp.DeviceJSON)
	}

	if sp.UserAgent != "" && (sp.SecChUa == "" || sp.SecChUaMobile == "" || sp.SecChUaPlatform == "") {
		p := profileFromUserAgent(sp.UserAgent)
		if sp.SecChUa == "" {
			sp.SecChUa = p.SecChUa
		}
		if sp.SecChUaMobile == "" {
			sp.SecChUaMobile = p.SecChUaMobile
		}
		if sp.SecChUaPlatform == "" {
			sp.SecChUaPlatform = p.SecChUaPlatform
		}
	}
}

func (sp *SavedProfile) HasCapturedCaptchaProfile() bool {
	if sp == nil {
		return false
	}
	return strings.TrimSpace(sp.DeviceJSON) != "" && strings.TrimSpace(sp.BrowserFp) != ""
}

func (sp *SavedProfile) CaptchaHTTPProfile(fallback Profile) Profile {
	if sp == nil || strings.TrimSpace(sp.UserAgent) == "" {
		return fallback
	}
	p := sp.Profile
	if p.SecChUa == "" || p.SecChUaMobile == "" || p.SecChUaPlatform == "" {
		derived := profileFromUserAgent(p.UserAgent)
		if p.SecChUa == "" {
			p.SecChUa = derived.SecChUa
		}
		if p.SecChUaMobile == "" {
			p.SecChUaMobile = derived.SecChUaMobile
		}
		if p.SecChUaPlatform == "" {
			p.SecChUaPlatform = derived.SecChUaPlatform
		}
	}
	return p
}

func decodeMaybeFormValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return strings.TrimSpace(decoded)
}

func profileFromUserAgent(ua string) Profile {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	}
	lower := strings.ToLower(ua)
	major := "146"
	re := regexp.MustCompile(`(?:Chrome|Chromium|Edg)/(\d+)`)
	if m := re.FindStringSubmatch(ua); len(m) > 1 {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			major = strconv.Itoa(n)
		}
	}
	brand := "Google Chrome"
	if strings.Contains(lower, "edg/") {
		brand = "Microsoft Edge"
	}
	platform := `"Windows"`
	switch {
	case strings.Contains(lower, "android"):
		platform = `"Android"`
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		platform = `"iOS"`
	case strings.Contains(lower, "macintosh"):
		platform = `"macOS"`
	case strings.Contains(lower, "linux") || strings.Contains(lower, "x11"):
		platform = `"Linux"`
	}
	mobile := "?0"
	if strings.Contains(lower, " mobile") || strings.Contains(lower, "android") || strings.Contains(lower, "iphone") {
		mobile = "?1"
	}
	return Profile{
		UserAgent:       ua,
		SecChUa:         `"Chromium";v="` + major + `", "Not-A.Brand";v="24", "` + brand + `";v="` + major + `"`,
		SecChUaMobile:   mobile,
		SecChUaPlatform: platform,
	}
}

// profileList contains paired User-Agent and Client Hints strings.
var profileList = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Microsoft Edge";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
		SecChUa:         `"Firefox";v="132", "Not-A.Brand";v="8", "Mozilla Firefox";v="132"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
}

var androidProfiles = []Profile{
	{
		UserAgent:       "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
		SecChUa:         `"Chromium";v="129", "Not-A.Brand";v="24", "Google Chrome";v="129"`,
		SecChUaMobile:   "?1",
		SecChUaPlatform: `"Android"`,
	},
}

var iosProfiles = []Profile{
	{
		UserAgent:       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		SecChUa:         `"Safari";v="17", "Not-A.Brand";v="24", "Apple Safari";v="17"`,
		SecChUaMobile:   "?1",
		SecChUaPlatform: `"iOS"`,
	},
}

var activeFingerprint = "chrome"

func SetActiveFingerprint(fp string) {
	activeFingerprint = fp
}

func GetActiveFingerprint() string {
	return activeFingerprint
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	switch activeFingerprint {
	case "android":
		return androidProfiles[rand.Intn(len(androidProfiles))]
	case "ios":
		return iosProfiles[rand.Intn(len(iosProfiles))]
	case "safari":
		return profileList[4] // Using macOS Chrome as approximation for Safari if no specific Safari profile exists, or implement one. Actually, let's just use iOS for safari or macos.
	case "firefox":
		return profileList[len(profileList)-1]
	default:
		// chrome, or unknown, pick from first few chrome profiles
		return profileList[rand.Intn(3)]
	}
}
