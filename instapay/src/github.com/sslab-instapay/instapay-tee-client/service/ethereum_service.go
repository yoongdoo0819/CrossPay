package service

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client -ltee

#include "app.h"
*/
import "C"
import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"reflect"
	"strings"
	"time"
	"unsafe"
	//"crypto/ecdsa"

	//"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/sslab-instapay/instapay-tee-client/config"
	instapay "github.com/sslab-instapay/instapay-tee-client/contracts"
	"github.com/sslab-instapay/instapay-tee-client/model"
	serverPb "github.com/sslab-instapay/instapay-tee-client/proto/server"
	"google.golang.org/grpc"
)

func SendOpenChannelTransaction(deposit int, otherAddress string) (string, error) {

	client, err := ethclient.Dial("ws://" + config.EthereumConfig["wsHost"] + ":" + config.EthereumConfig["wsPort"])
//	client, err := ethclient.Dial("http://141.223.121.164:8555")
	if err != nil {
		log.Println("ee", err)
	}

	account := config.GetAccountConfig()
	address := common.HexToAddress(config.GetAccountConfig().PublicKeyAddress)
	nonce, err := client.PendingNonceAt(context.Background(), address)

	fmt.Println("address########## : ", address.Hex());

	convertNonce := C.uint(nonce)
	owner := []C.uchar(account.PublicKeyAddress[2:])
	receiver := []C.uchar(otherAddress[2:])
	newDeposit := C.uint(uint32(deposit))
	SigLen := C.uint(0)

	fmt.Println("account: ", account);
	fmt.Println("owner : ", &owner[0]);
	fmt.Println("otherAddress: ", otherAddress);
	fmt.Println("address : ", address.Hex());
	fmt.Println("receiver : %s \n", &receiver[0]);

/*
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(1000000000000000000) // in wei (1 eth)
	gasLimit := uint64(2100000)                // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
/*
	contractAddr := common.HexToAddress("0x74DD27a41b01EB8B05630D256Eec6FE06e1ADE91")
	var data []byte 
	data = []byte("0x10cae21a000000000000000000000000ead11aa9f7638d85af59e60bb31f01634168d2a9")
	*/
	//toAddress := address
//	var data []byte
/*	tx := types.NewTransaction(nonce, contractAddr, value, gasLimit, gasPrice, data)
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	
	ts := types.Transactions{signedTx}
	rawTxBytes := ts.GetRlp(0)
	rawTxHex := hex.EncodeToString(rawTxBytes)

	rawTxBytes2, err := hex.DecodeString(rawTxHex)
	tx2 := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes2, &tx2)
*/
/*
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent : %s", signedTx.Hash().Hex())
	*/

	//C.ecall_test_func_w();

	fmt.Println(" ====================== CREATE CHANNEL START IN ENCLAVE ================ \n");
	var sig *C.uchar = C.ecall_create_channel_w(convertNonce, &owner[0], &receiver[0], newDeposit, &SigLen)
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(sig)),
		Len:  int(SigLen),
		Cap:  int(SigLen),
	}
	fmt.Println(" ====================== CREATE CHANNEL END IN ENCLAVE  ================ \n");

	s := *(*[]C.uchar)(unsafe.Pointer(&hdr))
	var convertedRawTx string
	convertedRawTx = fmt.Sprintf("%02x", s)
	rawTxBytes, err := hex.DecodeString(convertedRawTx)
	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)
	// rawTxHex := hex.EncodeToString(rawTxBytes)
	fmt.Println("rawTxHex : ", hex.EncodeToString(rawTxBytes))
	for i := 0; i < len(tx.Data()); i++ {
		fmt.Printf("%02x", tx.Data()[i])
	}
	fmt.Println()
	msg, err := tx.AsMessage(types.NewEIP155Signer(tx.ChainId()))
	if err != nil {
		log.Fatal(err)
	}

	v, r, _ := tx.RawSignatureValues()
	fmt.Println("v : ", v, " r : ", r, " s : ")
	fmt.Println()
	
	fromAddr, err := types.NewEIP155Signer(tx.ChainId()).Sender(tx)
	if err != nil {
		log.Fatal(err)
	}
	for i:= 0; i<20; i++ {
		fmt.Printf("%02x", fromAddr[i])
	}
	fmt.Println()
	fmt.Println("fromAddr : ", fromAddr.Hex())
	fmt.Println("chainId: ", tx.ChainId())
	fmt.Println("Sender : ", msg.From().Hex())
	fmt.Println("Receiver: ", msg.To().Hex())
//	fmt.Println("Data : ", common.HexToAddress(msg.Data()))
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Println("error : ", err)
	}
	fmt.Println("TX hash : ", tx.Hash().Hex())

	defer C.free(unsafe.Pointer(sig))

	return tx.Hash().Hex(), nil
}

func SendCloseChannelTransaction(channelId int64) {

	client, err := ethclient.Dial("ws://" + config.EthereumConfig["wsHost"] + ":" + config.EthereumConfig["wsPort"])
	if err != nil {
		log.Println(err)
	}


	account := config.GetAccountConfig()
	//address := common.HexToAddress(config.GetAccountConfig().PublicKeyAddress)

	address := common.HexToAddress(config.GetAccountConfig().PublicKeyAddress)
	nonce, err := client.PendingNonceAt(context.Background(), address)
	owner := []C.uchar(account.PublicKeyAddress[2:])

	if err != nil {
		log.Println(err)
	}


	fmt.Println("account: ", account);
	fmt.Println("owner : ", &owner[0]);
        fmt.Println("address : ", address)
	fmt.Println("channel Id : ", channelId)

	ChannelID := C.uint(channelId)
	SigLen := C.uint(0)

	var sig2 *C.uchar = C.ecall_close_channel_w(C.uint(nonce), &owner[0], ChannelID, &SigLen)
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(sig2)),
		Len:  int(SigLen),
		Cap:  int(SigLen),
	}

	s := *(*[]C.uchar)(unsafe.Pointer(&hdr))
	var convertedRawTx string
	convertedRawTx = fmt.Sprintf("%02x", s)
	rawTxBytes, err := hex.DecodeString(convertedRawTx)
	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)
	//client.SendTransaction(context.Background(), tx)

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Println("error : ", err)
	}
	fmt.Println("TX hash : ", tx.Hash().Hex())

	fromAddr, err := types.NewEIP155Signer(tx.ChainId()).Sender(tx)
	if err != nil {
		log.Fatal(err)
	}
	for i:= 0; i<20; i++ {
		fmt.Printf("%02x", fromAddr[i])
	}
	fmt.Println()
	fmt.Println("fromAddr : ", fromAddr.Hex())

}

func ListenContractEvent() {
	log.Println("---Start Listen Contract Event---")
	client, err := ethclient.Dial("ws://" + config.EthereumConfig["wsHost"] + ":" + config.EthereumConfig["wsPort"])
	//client, err := ethclient.Dial("http://141.223.121.164:8555")
	
	if err != nil {
		log.Fatal("Cannot connect Ethereum So, End Client")
	}
	contractAddress := common.HexToAddress(config.EthereumConfig["contractAddr"])
	fmt.Println("contract Addr : ", contractAddress)

	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
	}

	logs := make(chan types.Log)

	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("sub : ", sub)

	contractAbi, err := abi.JSON(strings.NewReader(string(instapay.InstapayABI)))
	if err != nil {
		log.Println(err)
	}

	fmt.Println("--- Listen Contract Event---")
	fmt.Println("query : ", query)
	fmt.Println("logs  : ", logs)
	fmt.Println("Abi   : ", contractAbi)
	fmt.Println()
	for {
		select {
		case err := <-sub.Err():
			log.Println(err)
		case vLog := <-logs:
			//var createChannelEvent = model.CreateChannelEvent{}
			//var closeChannelEvent = model.CloseChannelEvent{}
			//var ejectEvent = model.EjectEvent{}

			createChannelEvent := struct {
				Id	 *big.Int
				Owner	 common.Address
				Receiver common.Address
				Deposit	 *big.Int
			}{}
			closeChannelEvent := struct {
				Id	    *big.Int
				Ownerbal    *big.Int
				Receiverbal *big.Int
			}{}
			ejectEvent := struct {
				Pn 	 	*big.Int
				Registeredstage int
			}{}

			err := contractAbi.UnpackIntoInterface(&createChannelEvent, "EventCreateChannel", vLog.Data)
			//fmt.Println("a : ", a)
			if err == nil {
				log.Println("CreateChannel Event Emission")
				fmt.Printf("Channel ID       : %d\n", createChannelEvent.Id)
				fmt.Printf("Channel Onwer    : %s\n", createChannelEvent.Owner.Hex())
				fmt.Printf("Channel Receiver : %s\n", createChannelEvent.Receiver.Hex())
				fmt.Printf("Channel Deposit  : %d\n", createChannelEvent.Deposit)
				HandleCreateChannelEvent(createChannelEvent)
				continue
			}

			err = contractAbi.UnpackIntoInterface(&closeChannelEvent, "EventCloseChannel", vLog.Data)
			if err == nil {
				log.Print("CloseChannel Event Emission")
				fmt.Printf("Channel ID       : %d\n", closeChannelEvent.Id)
				fmt.Printf("Owner Balance    : %d\n", closeChannelEvent.Ownerbal)
				fmt.Printf("Receiver Balance : %d\n", closeChannelEvent.Receiverbal)
				HandleCloseChannelEvent(closeChannelEvent)
				continue
			}

			err = contractAbi.UnpackIntoInterface(&ejectEvent, "EventEject", vLog.Data)
			if err == nil {
				fmt.Printf("Payment Number   : %d\n", ejectEvent.Pn)
				fmt.Printf("Stage            : %d\n", ejectEvent.Registeredstage)
				continue
			}
		}
	}
}

func HandleCreateChannelEvent(event model.CreateChannelEvent) error {

	account := config.GetAccountConfig()
	log.Println("----- Handle Create Channel Event ----")

	if strings.ToLower(event.Receiver.String()) == config.GetAccountConfig().PublicKeyAddress {
		// CASE IN CHANNEL
		channelId := C.uint(uint32(event.Id.Int64()))
		owner := []C.uchar(account.PublicKeyAddress[2:])
		sender := []C.uchar(event.Owner.Hex()[2:])
		deposit := C.uint(uint32(event.Deposit.Int64()))
		fmt.Println("RECEIVE CREATE CHANNEL")
		C.ecall_receive_create_channel_w(channelId, &sender[0], &owner[0], deposit)
	} else if strings.ToLower(event.Owner.String()) == config.GetAccountConfig().PublicKeyAddress {
		// CASE OUT CHANNEL
		channelId := C.uint(uint32(event.Id.Int64()))
		owner := []C.uchar(event.Receiver.Hex()[2:])
		sender := []C.uchar(account.PublicKeyAddress[2:])
		deposit := C.uint(uint32(event.Deposit.Int64()))
		fmt.Println("RECEIVE CREATE CHANNEL")
		C.ecall_receive_create_channel_w(channelId, &sender[0], &owner[0], deposit)
	}

	fmt.Println("HANDLE CREATE CHANNEL EVENT SUCCESS")
	connection, err := grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println("GRPC Connection Error")
		log.Println(err)
	}
	defer connection.Close()
	client := serverPb.NewServerClient(connection)

	clientContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var otherAddress string
	if event.Receiver.String() == config.GetAccountConfig().PublicKeyAddress {
		otherAddress = event.Owner.String()
	} else {
		otherAddress = event.Receiver.String()
	}

	// TODO 상대 아이피 주소  이런 것들 업데이트
	_, err = client.CommunicationInfoRequest(clientContext, &serverPb.Address{Addr: otherAddress})
	if err != nil {
		log.Println(err)
		return err
	}

	var defaultDirectory string
	if os.Getenv("channel_file") == "" {
		defaultDirectory = "./data/channel/c0"
	} else {
		defaultDirectory = os.Getenv("channel_file")
	}

	cf := C.CString(defaultDirectory)
	C.ecall_store_channel_data_w(cf)

	log.Println("----- Handle Create Channel Event END ----")
	return nil
}

func HandleCloseChannelEvent(event model.CloseChannelEvent) {

	log.Println("----- Handle Close Channel Event -----")
	channelId := C.uint(uint32(event.Id.Int64()))
	ownerBal := C.uint(uint32(event.Ownerbal.Int64()))
	receiverBal := C.uint(uint32(event.Receiverbal.Int64()))

	log.Println("----- Start Close Channel Event -----")
	C.ecall_receive_close_channel_w(channelId, ownerBal, receiverBal)

	var defaultDirectory string
	if os.Getenv("channel_file") == "" {
		defaultDirectory = "./data/channel/c0"
	} else {
		defaultDirectory = os.Getenv("channel_file")
	}

	cf := C.CString(defaultDirectory)
	C.ecall_store_channel_data_w(cf)
	log.Println("----- End Close Channel Event -----")

}

func HandleEjectEvent(event model.EjectEvent) {
	//TODO
}

func GetBalance() (big.Float, error) {

	account := common.HexToAddress(config.GetAccountConfig().PublicKeyAddress)
	client, err := ethclient.Dial("ws://" + config.EthereumConfig["wsHost"] + ":" + config.EthereumConfig["wsPort"])

	if err != nil {
		return *big.NewFloat(0), err
	}

	balance, err := client.BalanceAt(context.Background(), account, nil)

	if err != nil {
		return *big.NewFloat(0), err
	}
	log.Println(balance)

	floatBalance := new(big.Float)
	floatBalance.SetString(balance.String())
	ethValue := new(big.Float).Quo(floatBalance, big.NewFloat(math.Pow10(18)))

	return *ethValue, nil
}
