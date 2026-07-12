package main

import (
	"sync"
)

const (
	wgIfaceName           = "wdtt0"
	wgServerAddr          = "10.66.66.1"
	wgServerCIDR          = wgServerAddr + "/24"
	defaultInternalWGPort = 56001
	wgMTU                 = 1280
	keepalive             = 25
)

var dns = "1.1.1.1"

type ClientDevice struct {
	DeviceID string `json:"device_id"`
	IP       string `json:"ip"`
	PrivKey  string `json:"priv_key"`
	PubKey   string `json:"pub_key"`
}

type PasswordEntry struct {
	DeviceID      string `json:"device_id"`
	ExpiresAt     int64  `json:"expires_at"`
	DownBytes     int64  `json:"down_bytes"`
	UpBytes       int64  `json:"up_bytes"`
	VkHash        string `json:"vk_hash,omitempty"`
	Ports         string `json:"ports,omitempty"`
	IsDeactivated bool   `json:"is_deactivated,omitempty"`
}

type Database struct {
	MainPassword string                    `json:"main_password"`
	AdminID      string                    `json:"admin_id"`
	BotToken     string                    `json:"bot_token"`
	Passwords    map[string]*PasswordEntry `json:"passwords"`
	Devices      map[string]*ClientDevice  `json:"devices"`
}

var (
	db      *Database
	dbMutex sync.RWMutex // Изменено на RWMutex для параллельного чтения данных
	dbFile  string
)

var serverWrapKeys = newWrapKeyStore()

const (
	passChars             = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	generatedPasswordLen  = 16
	maxGeneratedPasswords = 10
)
