package hyperledger

import (
	bytes2 "bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"
	"gopkg.in/yaml.v2"
	log "github.com/sirupsen/logrus"


	cbor "github.com/brianolson/cbor_go"
	"github.com/golang/protobuf/proto"
	"github.com/brocaar/lora-app-server/internal/integration"
	"github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/batch_pb2"
	"github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/protobuf/transaction_pb2"
	"github.com/brocaar/lora-app-server/internal/integration/hyperledger/sawtooth-sdk-go/signing"
)

// Integration implements the Hyperledger integration.
type Integration struct {
	url			string
	signer		*signing.Signer
	deviceName	string
}

// Config holds the hyperledger integration configuration.
type Config struct {
	url     string `mapstructure:"url"`
	keyfile string `mapstructure:"keyfile"`
}

func Sha512HashValue(value string) string {
	hashHandler := sha512.New()
	hashHandler.Write([]byte(value))
	return strings.ToLower(hex.EncodeToString(hashHandler.Sum(nil)))
}

func New(conf Config) (*Integration, error) {
	keyfile, err := GetKeyfile(conf.keyfile)
	if err != nil {
		log.Fatal(err)
	}
	url := conf.url
	return NewIntegration(url, keyfile)
}

func GetKeyfile(keyfile string) (string, error) {
	if keyfile == "" {
		username, err := user.Current()
		if err != nil {
			return "", err
		}
		return path.Join(
			username.HomeDir, ".sawtooth", "keys", username.Username+".priv"), nil
	} else {
		return keyfile, nil
	}
}

func NewIntegration(url string, keyfile string) (*Integration, error) {

	var privateKey signing.PrivateKey
	if keyfile == "" {
		// Read private key file
		privateKeyStr, err := ioutil.ReadFile(keyfile)
		if err != nil {
			log.Fatal(err)
		}
		// Get private key object
		privateKey = signing.NewSecp256k1PrivateKey(privateKeyStr)
	} else {
		privateKey = signing.NewSecp256k1Context().NewRandomPrivateKey()
	}
	cryptoFactory := signing.NewCryptoFactory(signing.NewSecp256k1Context())
	signer := cryptoFactory.NewSigner(privateKey)
	return &Integration{url, signer, "testing"}, nil
}

func (i *Integration) sendRequest(
	apiSuffix string,
	data []byte,
	contentType string,
	name string) (string, error){
	log.Println("got this far 8")
	// Construct URL
	var url string
	log.Printf("I.url = %s",i.url)
	if strings.HasPrefix(i.url, "http://") {
		url = fmt.Sprintf("%s/%s", "http://rest-api:8008", apiSuffix)
	} else {
		url = fmt.Sprintf("http://%s/%s", "rest-api:8008", apiSuffix)
	}

	// Send request to validator URL
	var response *http.Response
	var err error
	if len(data) > 0 {
		response, err = http.Post(url, contentType, bytes2.NewBuffer(data))
	} else {
		response, err = http.Get(url)
	}
	log.Printf("url is %s",url)
	if err != nil {
			log.Fatal("Failed to connect to REST API: %v", err)
	}
	log.Println("got this far 9")
	if response.StatusCode == 404 {
		log.Fatal(fmt.Sprintf("No such key: %s", name))
	} else if response.StatusCode >= 400 {
			log.Fatal("Error %d: %s", response.StatusCode, response.Status)
	}
	log.Println("got this far 10")
	defer response.Body.Close()
	reponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal("Error reading response: %v", err)
	}
	log.Println("got this far 9")
	return string(reponseBody), nil
}

// SendDataUp sends an uplink data payload.
func (i *Integration) SendDataUp(pl integration.DataUpPayload) error {
	log.WithFields(log.Fields{
		"dev_eui": pl.DevEUI,
	}).Info("integration/hyperledger: publishing data-up payload")
	data, err := json.Marshal(pl)
	if err != false {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// SendJoinNotification sends a join notification.
func (i *Integration) SendJoinNotification(pl integration.JoinNotification) error {
	log.WithFields(log.Fields{
		"dev_eui": pl.DevEUI,
	}).Info("integration/hyperledger: publishing data-join payload")
	data, err := json.Marshal(pl.DevEUI)
	if err != nil {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// SendACKNotification sends an ack notification.
func (i *Integration) SendACKNotification(pl integration.ACKNotification) error {
	log.WithFields(log.Fields{
		"dev_eui": pl.DevEUI,
	}).Info("integration/hyperledger: publishing data-ack payload")
	data, err := json.Marshal(pl.DevEUI)
	if err != nil {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// SendErrorNotification sends an error notification.
func (i *Integration) SendErrorNotification(pl integration.ErrorNotification) error {
	log.WithFields(log.Fields{
		"dev_eui": pl.DevEUI,
	}).Info("integration/hyperledger: publishing data-error payload")
	data, err := json.Marshal(pl.ApplicationID)
	if err != nil {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// SendStatusNotification sends a status notification.
func (i *Integration) SendStatusNotification(pl integration.StatusNotification) error {
	data, err := json.Marshal(pl.Battery)
	if err != nil {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// SendLocationNotification sends a location notification.
func (i *Integration) SendLocationNotification(pl integration.LocationNotification) error {
	log.WithFields(log.Fields{
		"dev_eui": pl.DevEUI,
	}).Info("integration/hyperledger: publishing data-location payload")
	data, err := json.Marshal(pl.DevEUI)
	if err != nil {
		log.Fatal(err)
	}
	return i.publish(data, i.deviceName)
}

// DataDownChan return nil.
func (i *Integration) DataDownChan() chan integration.DataDownPayload {
	return nil
}

// Close closes the integration.
func (i *Integration) Close() error {
	return nil
}

func (i *Integration) publish(data []byte, deveui string) error{
	i.sendTransaction(VERB_SET, deveui, data, 5)
	log.Println("got this far 2")
	return nil
}

func (i *Integration) sendTransaction(
	verb string, name string, value []byte, wait uint) (string, error) {
	// construct the payload information in CBOR format
	payloadData := make(map[string]interface{})
	payloadData["Verb"] = verb
	payloadData["Name"] = name
	payloadData["Value"] = value
	payload, err := cbor.Dumps(payloadData)
	log.Println("got this far 3")
	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to construct CBOR: %v", err))
	}

	// construct the address
	address := i.getAddress(name)

	// Construct TransactionHeader
	rawTransactionHeader := transaction_pb2.TransactionHeader{
		SignerPublicKey:  i.signer.GetPublicKey().AsHex(),
		FamilyName:       FAMILY_NAME,
		FamilyVersion:    FAMILY_VERSION,
		Dependencies:     []string{}, // empty dependency list
		Nonce:            strconv.Itoa(rand.Int()),
		BatcherPublicKey: i.signer.GetPublicKey().AsHex(),
		Inputs:           []string{address},
		Outputs:          []string{address},
		PayloadSha512:    Sha512HashValue(string(payload)),
	}
	transactionHeader, err := proto.Marshal(&rawTransactionHeader)
	if err != nil {
		return "", errors.New(
			fmt.Sprintf("Unable to serialize transaction header: %v", err))
	}
	log.Println("got this far 4")
	// Signature of TransactionHeader
	transactionHeaderSignature := hex.EncodeToString(
		i.signer.Sign(transactionHeader))

	// Construct Transaction
	transaction := transaction_pb2.Transaction{
		Header:          transactionHeader,
		HeaderSignature: transactionHeaderSignature,
		Payload:         []byte(payload),
	}
	log.Println("got this far 5")
	// Get BatchList
	rawBatchList, err := i.createBatchList(
		[]*transaction_pb2.Transaction{&transaction})
	if err != nil {
		return "", errors.New(
			fmt.Sprintf("Unable to construct batch list: %v", err))
	}
	batchId := rawBatchList.Batches[0].HeaderSignature
	batchList, err := proto.Marshal(&rawBatchList)
	if err != nil {
		return "", errors.New(
			fmt.Sprintf("Unable to serialize batch list: %v", err))
	}
	log.Println("got this far 6")
	if wait > 0 {
		waitTime := uint(0)
		startTime := time.Now()
		response, err := i.sendRequest(
			BATCH_SUBMIT_API, batchList, CONTENT_TYPE_OCTET_STREAM, name)
		if err != nil {
			return "", err
		}
		for waitTime < wait {
			status, err := i.getStatus(batchId, wait-waitTime)
			if err != nil {
				return "", err
			}
			waitTime = uint(time.Now().Sub(startTime))
			if status != "PENDING" {
				return response, nil
			}
		}
		return response, nil
	}
	log.Println("got this far 7")
	return i.sendRequest(
		BATCH_SUBMIT_API, batchList, CONTENT_TYPE_OCTET_STREAM, name)
}

func (i *Integration) getPrefix() string {
	return Sha512HashValue(FAMILY_NAME)[:FAMILY_NAMESPACE_ADDRESS_LENGTH]
}

func (i *Integration) getAddress(name string) string {
	prefix := i.getPrefix()
	nameAddress := Sha512HashValue(name)[FAMILY_VERB_ADDRESS_LENGTH:]
	return prefix + nameAddress
}

func (i *Integration) createBatchList(
	transactions []*transaction_pb2.Transaction) (batch_pb2.BatchList, error) {

	// Get list of TransactionHeader signatures
	transactionSignatures := []string{}
	for _, transaction := range transactions {
		transactionSignatures =
			append(transactionSignatures, transaction.HeaderSignature)
	}

	// Construct BatchHeader
	rawBatchHeader := batch_pb2.BatchHeader{
		SignerPublicKey: i.signer.GetPublicKey().AsHex(),
		TransactionIds:  transactionSignatures,
	}
	batchHeader, err := proto.Marshal(&rawBatchHeader)
	if err != nil {
		return batch_pb2.BatchList{}, errors.New(
			fmt.Sprintf("Unable to serialize batch header: %v", err))
	}

	// Signature of BatchHeader
	batchHeaderSignature := hex.EncodeToString(
		i.signer.Sign(batchHeader))

	// Construct Batch
	batch := batch_pb2.Batch{
		Header:          batchHeader,
		Transactions:    transactions,
		HeaderSignature: batchHeaderSignature,
	}

	// Construct BatchList
	return batch_pb2.BatchList{
		Batches: []*batch_pb2.Batch{&batch},
	}, nil
}

func (i *Integration) getStatus(
	batchId string, wait uint) (string, error) {

	// API to call
	apiSuffix := fmt.Sprintf("%s?id=%s&wait=%d",
		BATCH_STATUS_API, batchId, wait)
	response, err := i.sendRequest(apiSuffix, []byte{}, "", "")
	if err != nil {
		return "", err
	}

	responseMap := make(map[interface{}]interface{})
	err = yaml.Unmarshal([]byte(response), &responseMap)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error reading response: %v", err))
	}
	entry :=
		responseMap["data"].([]interface{})[0].(map[interface{}]interface{})
	return fmt.Sprint(entry["status"]), nil
}

