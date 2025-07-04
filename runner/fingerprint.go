package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
)

type Fingerprint struct {
	CICDPass      bool     `json:"cicd_pass"`
	CName         []string `json:"cname"`
	Discussion    string   `json:"discussion"`
	Documentation string   `json:"documentation"`
	Fingerprint   string   `json:"fingerprint"`
	HTTPStatus    *int     `json:"http_status"`
	NXDomain      bool     `json:"nxdomain"`
	Service       string   `json:"service"`
	Status        string   `json:"status"`
	Vulnerable    bool     `json:"vulnerable"`
}

var (
	fingerprintURL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
	localFolder    = ".jmk48over"
	localFileName  = "fingerprints.json"
)

// Fingerprints memuat database fingerprint dari file lokal
func Fingerprints() ([]Fingerprint, error) {
	var fingerprints []Fingerprint

	filePath, err := GetFingerprintPath()
	if err != nil {
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}

	if err := json.Unmarshal(content, &fingerprints); err != nil {
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}

	return fingerprints, nil
}

// GetFingerprintPath menentukan path lokal fingerprints.json
func GetFingerprintPath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("GetFingerprintPath: %v", err)
	}
	dir := filepath.Join(home, localFolder)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, localFileName), nil
}

// DownloadFingerprints fetch data fingerprint dari upstream
func DownloadFingerprints() error {
	destPath, err := GetFingerprintPath()
	if err != nil {
		return err
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("DownloadFingerprints: %v", err)
	}
	defer out.Close()

	resp, err := http.Get(fingerprintURL)
	if err != nil {
		return fmt.Errorf("DownloadFingerprints: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("DownloadFingerprints: %v", err)
	}

	return nil
}

// UpdateFingerprints adalah alias untuk DownloadFingerprints
func UpdateFingerprints() error {
	return DownloadFingerprints()
}

// CheckIntegrity membandingkan isi lokal dan upstream fingerprints.json
func CheckIntegrity() (bool, error) {
	localPath, err := GetFingerprintPath()
	if err != nil {
		return false, fmt.Errorf("CheckIntegrity: %v", err)
	}

	localData, err := os.ReadFile(localPath)
	if err != nil {
		return false, fmt.Errorf("CheckIntegrity: %v", err)
	}

	resp, err := http.Get(fingerprintURL)
	if err != nil {
		return false, fmt.Errorf("CheckIntegrity: %v", err)
	}
	defer resp.Body.Close()

	upstreamData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("CheckIntegrity: %v", err)
	}

	return string(localData) == string(upstreamData), nil
}
