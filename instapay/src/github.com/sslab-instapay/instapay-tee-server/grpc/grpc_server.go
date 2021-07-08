package grpc

/*
//#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
//#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

#cgo CFLAGS: -I /home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server 

//#include "app.h"
#include "message.h"
#include "cross_message.h"

#include <stdio.h>
#include <string.h>

void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature)
{
	unsigned char *msg32;
	int recid;

	// secp256k1 
	//secp256k1_context* secp256k1_ctx = NULL;
	//secp256k1_ecdsa_recoverable_signature sig;

	unsigned char output64[64];

        // sha3 (keccak256) 
	//sha3_context sha3_ctx;

	// hashing the byte stream 
	//sha3_Init256(&sha3_ctx);
	//sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
	//sha3_Update(&sha3_ctx, original_msg, msg_size);
	//msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

	// ECDSA sign on the message
	//secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	//secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, msg32, seckey, NULL, NULL);
	//secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, output64, &recid, &sig);

	//memcpy(signature, output64, 32);  // copy r
	//memcpy(signature + 32, output64 + 32, 32);  // copy s
	//memcpy(&signature[64], &recid, 1);  // copy v (recovery id)

	//secp256k1_context_destroy(secp256k1_ctx);
}

void ecall_create_ag_req_msg(unsigned int payment_num, unsigned int payment_size, unsigned int *channel_ids, int *amount, unsigned char *req_msg, unsigned char *req_sig)
{
	//    printf("%d AG REQ CREATED START !!!!!!!!!!!!!\n", payment_num);

	unsigned char req_signature[65] = {0, };
	unsigned char *seckey_arr;// = (unsigned char*)"5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5";
	unsigned char *seckey;// = ::arr_to_bytes(seckey_arr, 64);

	Message request;

	memset((unsigned char*)&request, 0x00, sizeof(Message));

	//create agreement request message 
	
   	//request.type = AG_REQ;
	//request.payment_num = payment_num;
	//request.payment_size = payment_size;
	//memcpy(request.channel_ids, channel_ids, sizeof(unsigned int) * payment_size);
	//memcpy(request.payment_amount, amount, sizeof(int) * payment_size);
	
	sign_message((unsigned char*)&request, sizeof(Message), seckey, req_signature);

        memcpy(req_msg, (unsigned char*)&request, sizeof(Message));
	memcpy(req_sig, req_signature, 65);

	//free(seckey);
	return;
}

int verify_ag_res_msg(unsigned char *res_msg)
{
	MessageRes *res = (MessageRes*)res_msg;

	// step 1. verify signature 
	// step 2. check that message type is 'AG_RES' 

	if(res->type != AG_RES || res->e != 1) {
		//*is_verified = 1;
		printf("NOT AG RES %d %d \n", AG_RES, res->e);
		return 0;
	}

	return 1;
}

int verify_ud_res_msg(unsigned char *res_msg)
{
	MessageRes *res = (MessageRes*)res_msg;

	// step 1. verify signature 
	// step 2. check that message type is 'AG_RES' 

	if(res->type != UD_RES || res->e != 1) {
		//*is_verified = 1;
		//printf("NOT UD RES \n");
		return 0;
	}

	return 1;
}

int verify_cross_ag_req_msg(unsigned char *req_msg)
{
	Cross_Message *req = (Cross_Message*)req_msg;

	// step 1. verify signature 
	// step 2. check that message type is 'AG_RES' 

	if(req->type != CROSS_ALL_PREPARE_REQ) {
		//*is_verified = 1;
		printf("NOT CROSS AG REQ ############################ \n");
		return 0;
	}

	return 1;
}

int verify_cross_ud_req_msg(unsigned char *req_msg)
{
	Cross_Message *req = (Cross_Message*)req_msg;

	// step 1. verify signature 
	// step 2. check that message type is 'AG_RES' 

	if(req->type != CROSS_ALL_COMMIT_REQ) {
		//*is_verified = 1;
		printf("NOT CROSS UD REQ ############################ \n");
		return 0;
	}

	return 1;
}

int verify_cross_confirm_msg(unsigned char *req_msg)
{
	Cross_Message *req = (Cross_Message*)req_msg;

	// step 1. verify signature 
	// step 2. check that message type is 'AG_RES' 

	if(req->type != CROSS_ALL_CONFIRM_REQ) {
		//*is_verified = 1;
		printf("NOT CROSS CONFIRM REQ ############################ \n");
		return 0;
	}

	return 1;
}
*/
import "C"

import (
	//"encoding/hex"
	//"crypto/ecdsa"
	//"crypto/rand"
	//"crypto/elliptic"
	//"bytes"
	"net"
	"log"
	"fmt"
	"time"
	"os"
	"sync"
	"context"
	"strconv"
	"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-server/repository"
	//"github.com/sslab-instapay/instapay-tee-server/config"
	pbServer "github.com/sslab-instapay/instapay-tee-server/proto/server"
	pbClient "github.com/sslab-instapay/instapay-tee-server/proto/client"
	pbXServer"github.com/sslab-instapay/instapay-tee-server/proto/cross-server"

	"github.com/sslab-instapay/instapay-tee-server/config"
	//ch "github.com/sslab-instapay/instapay-tee-server/controller"

	"runtime"
	//"github.com/ivpusic/grpool"
	"github.com/panjf2000/ants"
	"unsafe"
	"reflect"
	//"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
	//secp256 "github.com/decred/dcrd/dcrec/secp256k1"
//	"github.com/decred/dcrd/dcrec/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/crypto"
//	"github.com/ubiq/go-ubiq/crypto/secp256k1"


	//"crypto/sha256"
)


type Payment struct {
	Pn int64

	Sender string
	MiddleMan string
	Receiver string
	Amount int64

	Sender2 string
	MiddleMan2 string
	Receiver2 string
	Amount2 int64

	PreparedSender int
	PreparedMiddleMan int
	PreparedReceiver int

	PreparedSender2 int
	PreparedMiddleMan2 int
	PreparedReceiver2 int

	CommittedSender int
	CommittedMiddleMan int
	CommittedReceiver int

	CommittedSender2 int
	CommittedMiddleMan2 int
	CommittedReceiver2 int

	Status string
}

type Participant struct {

	party[41] C.uchar
	payment_size C.uint
	channel_ids[2] C.uint
	payment_amount[2] C.int
}

type Message struct {
	/********* common *********/
	messageType C.uint

	/***** direct payment *****/
	channel_id C.uint
	amount C.int
	counter C.uint

	/*** multi-hop payment ****/
	payment_num C.uint
	/*
	unsigned int payment_size;		
	unsigned int channel_ids[2];
	int payment_amount[2];
	*/

	participant[3] Participant
	e C.uint
}

type Cross_Message struct {
	/********* common *********/
	cross_messageType C.uint

        /*** cross-payment ***/
        cross_paymentServer C.uint

	/***** direct payment *****/
        channel_id C.uint
	amount C.int
	counter C.uint

	/*** multi-hop payment ****/
	payment_num C.uint
	payment_size C.uint
	channel_ids[2] C.uint
	payment_amount[2] C.int
	e C.uint
}

var sendAgreementRequestPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {

	_SendAgreementRequest(i)
	wg.Done()
})

var sendUpdateRequestPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {

	_SendUpdateRequest(i)
	wg.Done()
})

var sendConfirmPaymentPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {

	_SendConfirmPayment(i)
	wg.Done()
})


var wg sync.WaitGroup
//var sendAgreementRequestPool
//var processTest sync.WaitGroup
//var pool = grpool.NewPool(100000, 50000)
var seckey = []byte{7, 82, 123, 120, 27, 150, 39, 52, 92, 112, 78, 214, 183, 112, 19, 207, 128, 181, 72, 226, 125, 146, 63, 253, 47, 199, 191, 20, 132, 98, 119, 201}

var clientAddr = make(map[string]string)

var connection, err = grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
var Client [100]pbServer.ServerClient //= pbServer.NewServerClient(connection)
var ClientContext [100]context.Context// : {context.WithTimeout(context.Background(), time.Second*180), }

var connClient = make(map[string][1000]*grpc.ClientConn)

var channelId = 1
var PaymentNum = 1
var PaymentRequest [100000]Payment

var paymentInformation = make(map[string]PaymentInformation)
var p []string
var _paymentInformation = make(map[string]PaymentInformation)
var p2 []string

var addrToPubKey = make(map[string]string)

var connectionForClient = make(map[string]*grpc.ClientConn)
var connectionForXServer *grpc.ClientConn

var checkChFirstOrNot [10000]int
var paymentNumToChId [500000]int
var usingChannelIds [100000]chan bool
var ChComplete [500000]chan bool
var ch [500000]chan bool
var paymentEndEvent [200000]chan bool
var paymentEnd [200000]int
//var chComplete [100000]chan bool

var StartTime time.Time

var firstReq [100000]bool
var pnToChannelId [100000]int

var chPrepared [500000]int
var chCommitted [500000]int
var chConfirmed [500000]int

var chanCreateCheck = 0

var prepared [500000]int
var committed [500000]int

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
}

var rwMutex = new(sync.RWMutex)

type AG struct {
	pn int64
	address string
	paymentInformation map[string]PaymentInformation
	originalMessageByte []byte
	signatureByte []byte
}

type UD struct {
	pn int64
	address string
	paymentInformation map[string]PaymentInformation
	originalMessageByteArray [][]byte
	signatureByteArray [][]byte
}

var paymentPrepareMsgRes = make(map[string]AG)
var paymentCommitMsgRes = make(map[string]AG)

func _SendAgreementRequest(i interface{}) {


	pn := i.(AG).pn
	address := i.(AG).address
	originalMessageByte := i.(AG).originalMessageByte
	signatureByte := i.(AG).signatureByte


	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%1000])
	if client == nil {
		log.Fatal("client conn err")
	}
/*
	var uOriginal [44]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 44; i++ {
		uOriginal[i] = 'a'
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = 'b'
	}
*/

	r, err := client.AgreementRequest(context.Background(), &pbClient.AgreeRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println("client AgreementRequest err : ", err)
	}

	if r.Result {

		agreementOriginalMessage, _ := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)

		hash := crypto.Keccak256(r.OriginalMessage)
		pubKey, _ := secp256k1.RecoverPubkey(hash[:], r.Signature)
/*		for i:=0; i<32; i++ {
			fmt.Printf("%02x", pubKey[i])
		}
		fmt.Println(address)
*/

		var addr string

		for i:=0; i<32; i++ {
			addr += fmt.Sprintf("%02x", pubKey[i])
		}

		if addrToPubKey[address] != addr {
			fmt.Println("different pub")
		}

		if PaymentRequest[pn].Sender == address {
			PaymentRequest[pn].PreparedSender = 1
		} else if PaymentRequest[pn].MiddleMan == address {
			PaymentRequest[pn].PreparedMiddleMan = 1
		} else if PaymentRequest[pn].Receiver == address {
			PaymentRequest[pn].PreparedReceiver = 1
		} else if PaymentRequest[pn].Sender2 == address {
			PaymentRequest[pn].PreparedSender2 = 1
		} else if PaymentRequest[pn].MiddleMan2 == address {
			PaymentRequest[pn].PreparedMiddleMan2 = 1
		} else if PaymentRequest[pn].Receiver2 == address {
			PaymentRequest[pn].PreparedReceiver2 = 1
		}
//		secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)

		result := C.verify_ag_res_msg(agreementOriginalMessage)
		if result == 0 {
			fmt.Println("Message verification failed")
			return
		}

		var clientPrepareMsgRes = AG{}
		clientPrepareMsgRes.originalMessageByte = r.OriginalMessage
		clientPrepareMsgRes.signatureByte = r.Signature

		rwMutex.Lock()
		paymentPrepareMsgRes[strconv.FormatInt(pn, 10)+address] = clientPrepareMsgRes
		rwMutex.Unlock()


		ch[pn] <- true

	}
	/*
	rwMutex.Lock()
	C.ecall_update_sentagr_list_w(C.uint(pn), &([]C.uchar(address)[0]))
	rwMutex.Unlock()
	*/

	return
}

func _SendUpdateRequest(i interface{}) {

	pn := i.(UD).pn
	address := i.(UD).address
	originalMessageByteArray := i.(UD).originalMessageByteArray
	signatureByteArray := i.(UD).signatureByteArray

	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%1000])
	if client == nil {
		log.Fatal("client conn err")
	}

	rqm := pbClient.UpdateRequestsMessage{ /* convert AgreeRequestsMessage to UpdateRequestsMessage */
		PaymentNumber:   pn,
		OriginalMessage: originalMessageByteArray,
		Signature:       signatureByteArray,
	}

	r, err := client.UpdateRequest(context.Background(), &rqm)
	if err != nil {
		log.Fatal(err)
	}


	if r.Result == true {
		updateOriginalMessage, _ := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)

		hash := crypto.Keccak256(r.OriginalMessage)
		pubKey, _ := secp256k1.RecoverPubkey(hash[:], r.Signature)
/*		for i:=0; i<32; i++ {
			fmt.Printf("%02x", pubKey[i])
		}
*/
		var addr string

		for i:=0; i<32; i++ {
			addr += fmt.Sprintf("%02x", pubKey[i])
		}

		if addrToPubKey[address] != addr {
			fmt.Println("different pub")
		}

		if PaymentRequest[pn].Sender == address {
			PaymentRequest[pn].CommittedSender = 1
		} else if PaymentRequest[pn].MiddleMan == address {
			PaymentRequest[pn].CommittedMiddleMan = 1
		} else if PaymentRequest[pn].Receiver == address {
			PaymentRequest[pn].CommittedReceiver = 1
		} else if PaymentRequest[pn].Sender2 == address {
			PaymentRequest[pn].CommittedSender2 = 1
		} else if PaymentRequest[pn].MiddleMan2 == address {
			PaymentRequest[pn].CommittedMiddleMan2 = 1
		} else if PaymentRequest[pn].Receiver2 == address {
			PaymentRequest[pn].CommittedReceiver2 = 1
		}

//		secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)

		//fmt.Printf("Signature Verified? (from client) %v\n", verified)

		result := C.verify_ud_res_msg(updateOriginalMessage)
		if result == 0 {
			fmt.Println("Message UD Res verification failed")
			return
		}

		var clientCommitMsgRes = AG{}
		clientCommitMsgRes.originalMessageByte = r.OriginalMessage
		clientCommitMsgRes.signatureByte = r.Signature
		rwMutex.Lock()
		paymentCommitMsgRes[strconv.FormatInt(pn, 10)+address] = clientCommitMsgRes
		rwMutex.Unlock()

		ch[pn] <- true
	}
	/*
	rwMutex.Lock()
	C.ecall_update_sentupt_list_w(C.uint(pn), &([]C.uchar(address))[0])
	rwMutex.Unlock()
	*/

	return
}

func _SendConfirmPayment(i interface{}) {

	pn := i.(UD).pn
	address := i.(UD).address
	originalMessageByteArray := i.(UD).originalMessageByteArray
	signatureByteArray := i.(UD).signatureByteArray

	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%1000])
	if client == nil {
		log.Fatal("client conn err")
	}

	_, err = client.ConfirmPayment(context.Background(), &pbClient.ConfirmRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray}, )
	if err != nil {
		log.Println(err)
	}


	ch[pn] <- true
}


func WrapperAgreementRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByte []byte, signatureByte []byte) bool {
	/* remove C's address from p */
//	var q []string
//	q = p[0:2]

	//ChComplete[pn-1] <- true

	//return true
/*
	if firstReq[pnToChannelId[pn]] == true {
		//fmt.Printf("%d start... %d \n", pn, pnToChannelId[pn])
		firstReq[pnToChannelId[pn]] = false
	} else {
		//fmt.Println("waiting channelId...", pnToChannelId[pn])
		checkChannelIds(pn)
	}
*/

	var AG = AG{}
	AG.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		AG.pn = pn
		AG.address = address
		AG.originalMessageByte = originalMessageByte
		AG.signatureByte = signatureByte

		wg.Add(1)
		go sendAgreementRequestPool.Invoke(AG)
		//go SendAgreementRequest(pn, address, paymentInformation[address])
	}

/*		PaymentRequest[pn].PreparedSender == 1 &&
		PaymentRequest[pn].PreparedSender == 1 &&
		PaymentRequest[pn].PreparedSender == 1 && {
*/

	return true

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

	originalMessageByte, signatureByte = createMsgAndSig(int64(pn), p, paymentInformation, 5)

	originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
	signatureByteArray = append(signatureByteArray, signatureByte)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	if WrapperUpdateRequest(pn, p, paymentInformation, originalMessageByteArray, signatureByteArray) == true {
		return true
	} else {
		return false
	}
}

func WrapperUpdateRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArray [][]byte, signatureByteArray [][]byte) bool {

	var UD = UD{}
	UD.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = pn
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArray
		UD.signatureByteArray = signatureByteArray

		wg.Add(1)
		go sendUpdateRequestPool.Invoke(UD)

		//go SendUpdateRequest(pn, address, paymentInformation[address])
	}

	return true

	for i:= 1; i<=6; i++ {
		var data = <- ch[pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			chCommitted[pn]++
		}

		if chCommitted[pn] == 6 {
			break
		}
	}

	if PaymentRequest[pn].CommittedSender == 1 &&
		PaymentRequest[pn].CommittedMiddleMan == 1 &&
		PaymentRequest[pn].CommittedReceiver == 1 {
			PaymentRequest[pn].Status = "COMMITTED"
		}

	//fmt.Println("ALL UD")

	var originalMessageByteArrayForConfirm [][]byte
	var signatureByteArrayForConfirm [][]byte

	originalMessageByte, signatureByte := createMsgAndSig(int64(pn), p, paymentInformation, 7)

	originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, originalMessageByte)
	signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, signatureByte)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte
		rwMutex.Lock()
		originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	go WrapperConfirmPayment(int(pn), p, paymentInformation, originalMessageByteArrayForConfirm, signatureByteArrayForConfirm)

	for i:= 1; i<=6; i++ {
		var data = <- ch[pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			chConfirmed[pn]++
		}

		if chConfirmed[pn] == 6 {
			break
		}
	}

	go func() {
		ChComplete[paymentNumToChId[pn]] <- true
	}()

	paymentEndEvent[pn] <- true
	//fmt.Println("END!!")
	return true
}

func WrapperConfirmPayment(pn int, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArray [][]byte, signatureByteArray [][]byte) bool {
	/* update payment's status */
	//C.ecall_update_payment_status_to_success_w(C.uint(pn))

	var UD = UD{}
	//AG.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = int64(pn)
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArray
		UD.signatureByteArray = signatureByteArray

		wg.Add(1)
		go sendConfirmPaymentPool.Invoke(UD)
		//go SendConfirmPayment(pn, address)
	}

	return true
}

func SearchPath(pn int64, amount int64, firstTempChId int, secondTempChId int) ([]string, []string, map[string]PaymentInformation, map[string]PaymentInformation) {

	//log.Println("===== SearchPath Start =====")
	//var tempP = p// []string

	/* composing p */
/*
	p = append(p, "f55ba9376db959fab2af86d565325829b08ea3c4")
	p = append(p, "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")
	p = append(p, "70603f1189790fcd0fd753a7fef464bdc2c2ad36")
*/
	/* composing w */
	var channelInform1, channelInform2, channelInform3 []C.uint
	var amountInform1, amountInform2, amountInform3 []C.int

/*
	if firstReq[pnToChannelId[pn]] == true {
		//fmt.Printf("%d start... %d \n", pn, pnToChannelId[pn])
		firstReq[pnToChannelId[pn]] = false
	} else {
		//fmt.Println("waiting channelId...", pnToChannelId[pn])
		checkChannelIds(pn)
	}
*/
/*
	for ; ; {
		tempChannelId := channelId
		if usingChannelIds[tempChannelId] == true {
			channelId += 2
		} else {
			usingChannelIds[tempChannelId] = true
			break
		}

//		fmt.Println("start >>", channelId)
//		fmt.Println(usingChannelIds[tempChannelId])
//		time.Sleep(1000)
		if channelId >= 59 {
			channelId = 1
		}

	}
*/
//	rwMutex.Lock()
	channelInform1 = append(channelInform1, C.uint(firstTempChId))
	channelInform2 = append(channelInform2, C.uint(firstTempChId))
//	channelId++
	channelInform2 = append(channelInform2, C.uint(secondTempChId))
	channelInform3 = append(channelInform3, C.uint(secondTempChId))
//	channelId++
//	rwMutex.Unlock()
/*
	if channelId >= 9000 {
		channelId = 1
	}
*/
	amountInform1 = append(amountInform1, C.int(-amount))
	amountInform2 = append(amountInform2, C.int(amount))
	amountInform2 = append(amountInform2, C.int(-amount))
	amountInform3 = append(amountInform3, C.int(amount))

	paymentInform1 := PaymentInformation{ChannelInform: channelInform1, AmountInform: amountInform1}
	paymentInform2 := PaymentInformation{ChannelInform: channelInform2, AmountInform: amountInform2}
	paymentInform3 := PaymentInformation{ChannelInform: channelInform3, AmountInform: amountInform3}

	//paymentInformation := make(map[string]PaymentInformation)

	rwMutex.Lock()
	paymentInformation["f55ba9376db959fab2af86d565325829b08ea3c4"] = paymentInform1
	paymentInformation["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = paymentInform2
	paymentInformation["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = paymentInform3

	_paymentInformation["f4444529d6221122d1712c52623ba119a60609e3"] = paymentInform1
	_paymentInformation["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = paymentInform2
	_paymentInformation["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = paymentInform3
	rwMutex.Unlock()
	//log.Println("===== SearchPath End =====")
	return p, p2, paymentInformation, _paymentInformation
}

func (s *ServerGrpc) PaymentRequest(ctx context.Context, rq *pbServer.PaymentRequestMessage) (*pbServer.Result, error) {

	//log.Println("===== Payment Request Start =====")

	//from := rq.From
	//to := rq.To
	//pay : rq.Pn
	amount := rq.Amount

	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)

	rwMutex.Lock()

	firstTempChId := channelId
	secondTempChId := channelId+1

	go func() {
		paymentNumToChId[rq.Pn] = channelId
		if checkChFirstOrNot[paymentNumToChId[rq.Pn]] == 0 {    // if channel ID is used first,
			checkChFirstOrNot[paymentNumToChId[rq.Pn]] = 1
		} else {
			if <-ChComplete[paymentNumToChId[rq.Pn]] == true {} // else, wait
		}
	}()

	//tempPn := PaymentNum
	//pnToChannelId[int64(tempPn)] = channelId
	//PaymentNum++

	channelId+=2

	if channelId > 4500 {
		channelId = 1
	}
	rwMutex.Unlock()

        p, p2, paymentInformation, _paymentInformation = SearchPath(int64(rq.Pn), amount, firstTempChId, secondTempChId)

//	p, paymentInformation := SearchPath(int64(tempPn), amount, firstTempChId, secondTempChId)
/*
	var originalMessage *C.uchar// = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	var __signature[65] C.uchar
	var signature *C.uchar
*/
/*
	_sender := []C.uchar(p[0])
	_middleMan := []C.uchar(p[1])
	_receiver := []C.uchar(p[2])
*/
	
/*
	for ; ; {
		result =  C.ecall_create_ag_req_msg_temp_w(C.uint(tempPn), &_sender[0], &_middleMan[0], &_receiver[0] , C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage, &signature)

		if result == 9999 {
			break
		} else if result != 9999 {
			return &pbServer.Result{Result: false}, nil
		}
	}
*/
/*
	var Message = Message{}
	Message.messageType = 3	// AG_REQ

	//Message.channel_id = 1
	Message.amount = 1
	//Message.counter =0

	Message.payment_num = C.uint(tempPn)
	//var party = "f55ba9376db959fab2af86d565325829b08ea3c4"

	var Participant1 = Participant{}
	var Participant2 = Participant{}
	var Participant3 = Participant{}

	//      C.memcpy(Participant.party, []C.uchar(&_sender[0]), 41)
	for i := 0; i < 40; i++ {
		Participant1.party[i] = C.uchar(p[0][i])
	}

	for i := 0; i < 40; i++ {
		Participant2.party[i] = C.uchar(p[1][i])
	}

	for i := 0; i < 40; i++ {
		Participant3.party[i] = C.uchar(p[2][i])
	}

	Participant1.payment_size = C.uint(len(channelSlice1))
	Participant1.channel_ids[0] = channelSlice1[0]
	Participant1.payment_amount[0] = amountSlice1[0]

	Participant2.payment_size = C.uint(len(channelSlice2))
	Participant2.channel_ids[0] = channelSlice2[0]
	Participant2.payment_amount[0] = amountSlice2[0]
	Participant2.channel_ids[1] = channelSlice2[1]
	Participant2.payment_amount[1] = amountSlice2[1]

	Participant3.payment_size = C.uint(len(channelSlice3))
	Participant3.channel_ids[0] = channelSlice3[0]
	Participant3.payment_amount[0] = amountSlice3[0]

	Message.participant[0] = Participant1
	Message.participant[1] = Participant2
	Message.participant[2] = Participant3

	//Message.e = 1
*/

/*
	pkBytes, err := hex.DecodeString("5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5")
	if err != nil {
		fmt.Println(err)
		return &pbServer.Result{Result: false}, nil
	}

	fmt.Println("pubkey : ", pkBytes)
	privKey := secp256.PrivKeyFromBytes(pkBytes)
	//privKey := "aa"
	fmt.Println("type : ", reflect.TypeOf(privKey))
	fmt.Println("privkey: ", privKey)
	//pubKey  := secp256k1.PubKey(privKey)
	//fmt.Println("pubkey : ", pubKey)
*/
	//pubkey, seckey := secp256k1.generateKeyPair()

//	secp256k1.init()
/*	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := elliptic.Marshal(secp256k1.S256(), key.X, key.Y)
	fmt.Println("pubkey : ", pubkey)
	seckey := make([]byte, 32)
	blob := key.D.Bytes()
	copy(seckey[32-len(blob):], blob)
	fmt.Println("seckey : ", seckey)

	// Sign a message using the private key.

	originalMessage = (*C.uchar)(unsafe.Pointer(&Message))
	signature = (*C.uchar)(unsafe.Pointer(&__signature))

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
//	fmt.Println("original sig : ", signatureByte)

	messageHash := chainhash.HashB([]byte(originalMessageByte))
	fmt.Println("len : ", len(messageHash))
	_signature, err := secp256k1.Sign(messageHash, seckey)
	fmt.Println("signature : ", _signature)
	if err != nil {
		fmt.Println("error ", err)
		return &pbServer.Result{Result: false}, nil
	}

	var b = int(_signature[32])
	if b < 0 {
		fmt.Println("highest bit is negative: %d", b)
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		fmt.Println("highest bit: %d bit >> 7: %d", b, b>>7)
	}
	if (b & 0x80) == 0x80 {
		fmt.Println("highest bit: %d bit & 0x80: %d", b, b&0x80)
	}

	if len(pubkey) != 65 {
		fmt.Println("pubkey length mismatch: want: 65 have: %d", len(pubkey))
	}
	if len(seckey) != 32 {
		fmt.Println("seckey length mismatch: want: 32 have: %d", len(seckey))
	}
	if len(_signature) != 65 {
		fmt.Println("sig length mismatch: want: 65 have: %d", len(_signature))
	}
	recid := int(_signature[64])
	if recid > 4 || recid < 0 {
		fmt.Println("sig recid mismatch: want: within 0 to 4 have: %d", int(_signature[64]))
	}

	verified := secp256k1.VerifySignature(pubkey, messageHash, _signature)
	//verified := signature.Verify(messageHash, pubkey)
	fmt.Printf("Signature Verified? %v\n", verified)

	//_signature, err := privKey.Sign(messageHash)

	originalMessage = (*C.uchar)(unsafe.Pointer(&Message))
	signature = (*C.uchar)(unsafe.Pointer(&_signature))


	//fmt.Println("msg : ", originalMessage)
	//fmt.Println("sig : ", signature)
	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)

	fmt.Println("msg : ", originalMessageByte)
	fmt.Println("sig : ", signatureByte)

	verified = secp256k1.VerifySignature(pubkey, messageHash, _signature)
	//verified := signature.Verify(messageHash, pubkey)
	fmt.Printf("Signature Verified? %v\n", verified)
*/
	//fmt.Printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> PN : %d \n", int(PaymentNum))


/*
	for i := 0; i < len(p); i++ {
		C.ecall_add_participant_w(PaymentNum, &([]C.uchar(p[i]))[0])
	}
	C.ecall_update_sentagr_list_w(PaymentNum, &([]C.uchar(p[2]))[0])
*/

	var originalMessageByteForPrepare, signatureByteForPrepare []byte
	var originalMessageByteForPrepare2, signatureByteForPrepare2 []byte

	var originalMessageByteForCommit, signatureByteForCommit []byte
	var originalMessageByteForCommit2, signatureByteForCommit2 []byte

	var originalMessageByteForConfirm, signatureByteForConfirm []byte
	var originalMessageByteForConfirm2, signatureByteForConfirm2 []byte

	originalMessageByteForPrepare, signatureByteForPrepare = createMsgAndSig(rq.Pn, p, paymentInformation, 3)

	originalMessageByteForPrepare2, signatureByteForPrepare2 = createMsgAndSig(rq.Pn, p2, _paymentInformation, 3)

	go WrapperAgreementRequest(rq.Pn, p, paymentInformation, originalMessageByteForPrepare, signatureByteForPrepare) 

	go WrapperAgreementRequest(rq.Pn, p2, _paymentInformation, originalMessageByteForPrepare2, signatureByteForPrepare2) 

	for i:= 1; ; i++ {
		var data = <- ch[rq.Pn]
		//fmt.Printf("%d AG response %d \n", pn, i)
		if data == true {
			chPrepared[rq.Pn]++
		}

		if chPrepared[rq.Pn] == 6 {
			break
		}
	}

	if PaymentRequest[rq.Pn].PreparedSender == 1 &&
		PaymentRequest[rq.Pn].PreparedMiddleMan == 1 &&
		PaymentRequest[rq.Pn].PreparedReceiver == 1 {
			PaymentRequest[rq.Pn].Status = "PREPARED"
		}

	//fmt.Println("ALL AG")
	//return &pbServer.Result{Result: true}, nil

	var originalMessageByteArrayForCommit [][]byte
	var signatureByteArrayForCommit [][]byte

	originalMessageByteForCommit, signatureByteForCommit = createMsgAndSig(int64(rq.Pn), p, paymentInformation, 5)
	originalMessageByteForCommit2, signatureByteForCommit2 = createMsgAndSig(int64(rq.Pn), p2, _paymentInformation, 5)

	originalMessageByteArrayForCommit = append(originalMessageByteArrayForCommit, originalMessageByteForCommit)
	signatureByteArrayForCommit = append(signatureByteArrayForCommit, signatureByteForCommit)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArrayForCommit = append(originalMessageByteArrayForCommit, paymentPrepareMsgRes[strconv.FormatInt(rq.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForCommit = append(signatureByteArrayForCommit, paymentPrepareMsgRes[strconv.FormatInt(rq.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	var originalMessageByteArrayForCommit2 [][]byte
	var signatureByteArrayForCommit2 [][]byte

	originalMessageByteArrayForCommit2 = append(originalMessageByteArrayForCommit2, originalMessageByteForCommit2)
	signatureByteArrayForCommit2 = append(signatureByteArrayForCommit2, signatureByteForCommit2)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArrayForCommit2 = append(originalMessageByteArrayForCommit2, paymentPrepareMsgRes[strconv.FormatInt(rq.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForCommit2 = append(signatureByteArrayForCommit2, paymentPrepareMsgRes[strconv.FormatInt(rq.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	go WrapperUpdateRequest(rq.Pn, p, paymentInformation, originalMessageByteArrayForCommit, signatureByteArrayForCommit)

	go WrapperUpdateRequest(rq.Pn, p2, _paymentInformation, originalMessageByteArrayForCommit2, signatureByteArrayForCommit2)


	for i:= 1; ; i++ {
		var data = <- ch[rq.Pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			chCommitted[rq.Pn]++
		}

		if chCommitted[rq.Pn] == 6 {
			break
		}
	}

	if PaymentRequest[rq.Pn].CommittedSender == 1 &&
		PaymentRequest[rq.Pn].CommittedMiddleMan == 1 &&
		PaymentRequest[rq.Pn].CommittedReceiver == 1 {
			PaymentRequest[rq.Pn].Status = "COMMITTED"
		}

	//fmt.Println("ALL UD")
//	return &pbServer.Result{Result: true}, nil

	var originalMessageByteArrayForConfirm [][]byte
	var signatureByteArrayForConfirm [][]byte

	originalMessageByteForConfirm, signatureByteForConfirm = createMsgAndSig(int64(rq.Pn), p, paymentInformation, 7)
	originalMessageByteForConfirm2, signatureByteForConfirm2 = createMsgAndSig(int64(rq.Pn), p2, _paymentInformation, 7)

	originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, originalMessageByteForConfirm)
	signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, signatureByteForConfirm)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte
		rwMutex.Lock()
		originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rq.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rq.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	var originalMessageByteArrayForConfirm2 [][]byte
	var signatureByteArrayForConfirm2 [][]byte

	originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, originalMessageByteForConfirm2)
	signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, signatureByteForConfirm2)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte
		rwMutex.Lock()
		originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rq.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rq.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()

	}

	go WrapperConfirmPayment(int(rq.Pn), p, paymentInformation, originalMessageByteArrayForConfirm, signatureByteArrayForConfirm)

	go WrapperConfirmPayment(int(rq.Pn), p2, _paymentInformation, originalMessageByteArrayForConfirm2, signatureByteArrayForConfirm2)

	for i:= 1; ; i++ {
		var data = <- ch[rq.Pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			chConfirmed[rq.Pn]++
		}

		if chConfirmed[rq.Pn] == 6 {
			break
		}
	}

	go func() {
		ChComplete[paymentNumToChId[rq.Pn]] <- true
	}()

/*
	for i:= 1; ; i++ {
		var data = <- paymentEndEvent[rq.Pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			paymentEnd[rq.Pn]++
		}

		if paymentEnd[rq.Pn] == 2 {
			break
		}
	}
*/

	//fmt.Println("END!!")
	return &pbServer.Result{Result: true}, nil
}

func (s *ServerGrpc) CommunicationInfoRequest(ctx context.Context, address *pbServer.Address) (*pbServer.CommunicationInfo, error) {
	res, err := repository.GetClientInfo(address.Addr)
	if err != nil {
		log.Fatal(err)
	}

	return &pbServer.CommunicationInfo{IPAddress: res.IP, Port: int64(res.Port)}, nil
}

func StartGrpcServer() {

	ChanCreate()
	GrpcConnection()
	GetClientInfo()
	runtime.GOMAXPROCS(12)

	//processTest.Add(10000)
	//pool := grpool.NewPool(100, 50)

	grpcPort, err := strconv.Atoi(os.Getenv("grpc_port"))
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pbServer.RegisterServerServer(grpcServer, &ServerGrpc{})

	grpcServer.Serve(lis)
}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	//log.Println("----- convertByteToPointer Server Start -----")
	//var uOriginal [44]C.uchar
	var uOriginal [216]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 216; i++ {
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

//	log.Println("----- convertByteToPointer Server End -----")
	return cOriginalMsg, cSignature
}

func convertMsgResByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	//log.Println("----- convertByteToPointer Server Start -----")
	//var uOriginal [44]C.uchar
	var uOriginal [16]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 16; i++ {
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

//	log.Println("----- convertByteToPointer Server End -----")
	return cOriginalMsg, cSignature
}

func convertByteToPointerForCross(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	//log.Println("----- convertByteToPointer Server Start -----")
	//var uOriginal [44]C.uchar
	var uOriginal [44]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 44; i++ {
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

//	log.Println("----- convertByteToPointer Server End -----")
	return cOriginalMsg, cSignature
}

func convertPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

//	log.Println("----- convertPointerToByte Server Start -----")

	//fmt.Println(originalMsg)
	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(216),
		Cap:  int(216),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))
	//fmt.Println(replyMsgS)

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 216; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

//	C.free(unsafe.Pointer(originalMsg))
//	C.free(unsafe.Pointer(signature))

//	log.Println("----- convertPointerToByte Server End -----")
	return returnMsg, returnSignature
}

type PaymentInformation struct {
	ChannelInform []C.uint
	AmountInform  []C.int
}

/*
 *
 *instapay 3.0
 */

func (s *ServerGrpc) CrossPaymentPrepareRequest(ctx context.Context, rq *pbServer.CrossPaymentPrepareReqMessage) (*pbServer.CrossPaymentPrepareResult, error) {


	//log.Println("===== CROSS PAYMENT PREPARE START BY LV2 SERVER=====")

	//from := rq.From
	//to := rq.To
	amount := rq.Amount
	paymentNum := rq.Pn

	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)


	convertedOriginalMsg, _ := convertByteToPointerForCross(rq.OriginalMessage, rq.Signature)
	//C.ecall_cross_create_all_prepare_msg_w(convertedOriginalMsg, convertedSignatureMsg)

	secp256k1.VerifySignature([]byte("address"), rq.OriginalMessage, rq.Signature)
	C.verify_cross_ag_req_msg(convertedOriginalMsg)

	//C.ecall_cross_accept_request_w(&sender[0], &receiver[0], C.uint(amount), C.uint(PaymentNum))
	//p, paymentInformation := SearchPath(int64(PaymentNum), amount, 1, 2)

	/*
	for i := 0; i < len(p); i++ {
		C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(p[i]))[0])
	}
	C.ecall_cross_update_sentagr_list_w(C.uint(PaymentNum), &([]C.uchar(p[2]))[0])
	*/


	originalMessageByte, signatureByte := createMsgAndSig(int64(paymentNum), p, paymentInformation, 3)

	result := WrapperCrossAgreementRequest(int64(paymentNum), p, int64(amount), paymentInformation, originalMessageByte, signatureByte)

	if result == false {
		//
		return &pbServer.CrossPaymentPrepareResult{Result: false}, nil

		/*
		var originalMessageByteArray [][]byte
		var signatureByteArray [][]byte

		originalMessageByte, signatureByte = createMsgAndSig(int64(pn), p, paymentInformation, 5)

		originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
		signatureByteArray = append(signatureByteArray, signatureByte)

		for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

			rwMutex.Lock()
			originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
			signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
			rwMutex.Unlock()
		}

		XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
		if XServer == nil {
			log.Fatal("XServer conn err")
			return
		}

		XServerContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
		defer cancel()


		_, err := XServer.CrossPaymentPrepared(XServerContext, &pbXServer.CrossPaymentPrepareResMessage{Pn: pn, OriginalMessage: originalMessageByte, Signature: signatureByte, Result: true})
		if err != nil {
			log.Fatal("***** ERROR ***** ", err)
			return
		}
		*/
	} else {

/*

	connectionForXServer, err := grpc.Dial(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"], grpc.WithInsecure())
	log.Println(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"])

	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	//XServerContext, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()

	r, err := XServer.CrossPaymentPrepared(context.Background(), &pbXServer.CrossPaymentPrepareResMessage{Result: "true"})
	if err != nil {
		log.Println("CrossPaymentPrepared Err : ", err)
	}

	log.Println(r.GetResult())
*/
		originalMessageByte, signatureByte = createCrossMsgAndSig(int64(paymentNum), p, paymentInformation, 4, 13)

		return &pbServer.CrossPaymentPrepareResult{Result: true, OriginalMessage: originalMessageByte, Signature: signatureByte}, nil
	}
}
/*
func (s *pbServer) mustEmbedUnimplementedServerServer() (*pbServer.Result, error) {


	log.Println("===== unimplemented server =====")
	return &pbServer.Result{Result: true}, nil
}
*/

func (s *ServerGrpc) CrossPaymentCommitRequest(ctx context.Context, rq *pbServer.CrossPaymentCommitReqMessage) (*pbServer.CrossPaymentCommitResult, error) {


//	log.Println("===== CROSS PAYMENT COMMIT START BY LV2 SERVER =====")

	//from := rq.From
	//to := rq.To
	pn := rq.Pn
	//amount := rq.Amount
	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)

	convertedOriginalMsg, _ := convertByteToPointerForCross(rq.OriginalMessage, rq.Signature)

	secp256k1.VerifySignature([]byte("address"), rq.OriginalMessage, rq.Signature)
	C.verify_cross_ud_req_msg(convertedOriginalMsg)


	//C.ecall_cross_create_all_commit_msg_w(convertedOriginalMsg, convertedSignatureMsg)

	//PaymentNum := C.ecall_accept_request_w(&sender[0], &receiver[0], C.uint(amount))
//	p, paymentInformation := SearchPath(pn, amount, 1, 1)

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

	originalMessageByte, signatureByte := createMsgAndSig(int64(pn), p, paymentInformation, 5)

	originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
	signatureByteArray = append(signatureByteArray, signatureByte)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

	originalMessageByteArray = append(originalMessageByteArray, rq.OriginalMessage)
	signatureByteArray = append(signatureByteArray, rq.Signature)

	result := WrapperCrossUpdateRequest(int64(pn), p, paymentInformation, originalMessageByteArray, signatureByteArray)

	if result == true {

		originalMessageByte, signatureByte = createCrossMsgAndSig(int64(pn), p, paymentInformation, 8, 13)
		return &pbServer.CrossPaymentCommitResult{Result: true, OriginalMessage: originalMessageByte, Signature: signatureByte}, nil
	}
/*
	for i := 0; i < len(p); i++ {
		C.ecall_add_participant_w(PaymentNum, &([]C.uchar(p[i]))[0])
	}
	C.ecall_update_sentagr_list_w(PaymentNum, &([]C.uchar(p[2]))[0])
*/
	//go WrapperCrossAgreementRequest(int64(PaymentNum), p, paymentInformation)

/*
	connectionForXServer, err := grpc.Dial(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"], grpc.WithInsecure())
	log.Println(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"])

	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	//XServerContext, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()

	r, err := XServer.CrossPaymentCommitted(context.Background(), &pbXServer.CrossPaymentCommitResMessage{Result: true})
	if err != nil {
		log.Println("CrossPaymentCommitted Err : ", err)
	}

	log.Println(r.GetResult())
*/
//	log.Println("===== CROSS PAYMENT COMMIT END BY LV2 SERVER =====")

	return &pbServer.CrossPaymentCommitResult{Result: false}, nil
}

func (s *ServerGrpc) CrossPaymentConfirmRequest(ctx context.Context, rq *pbServer.CrossPaymentConfirmReqMessage) (*pbServer.CrossPaymentConfirmResult, error) {


//	log.Println("===== CROSS PAYMENT CONFIRM START BY LV2 SERVER =====")

	//from := rq.From
	//to := rq.To
	pn := rq.Pn
	//amount := rq.Amount
	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)

	convertedOriginalMsg, _ := convertByteToPointerForCross(rq.OriginalMessage, rq.Signature)
 
 	secp256k1.VerifySignature([]byte("address"), rq.OriginalMessage, rq.Signature)
	C.verify_cross_confirm_msg(convertedOriginalMsg)

	//C.ecall_cross_create_all_confirm_msg_w(convertedOriginalMsg, convertedSignatureMsg)

	//PaymentNum := C.ecall_accept_request_w(&sender[0], &receiver[0], C.uint(amount))
//	p, paymentInformation := SearchPath(pn, amount, 1, 2)

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

	originalMessageByte, signatureByte := createMsgAndSig(int64(pn), p, paymentInformation, 7)

	originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
	signatureByteArray = append(signatureByteArray, signatureByte)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentCommitMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentCommitMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

	originalMessageByteArray = append(originalMessageByteArray, rq.OriginalMessage)
	signatureByteArray = append(signatureByteArray, rq.Signature)

	go WrapperCrossConfirmPayment(int64(pn), p, paymentInformation, originalMessageByteArray, signatureByteArray)

	//go WrapperCrossConfirmPayment(int(pn), p, paymentInformation, originalMessageByteArray, signatureByteArray)
	//go WrapperCrossUpdateRequest(pn, p, paymentInformation)

//	log.Println("===== CROSS PAYMENT CONFIRM END BY LV2 SERVER =====")
	return &pbServer.CrossPaymentConfirmResult{Result: true}, nil
}

func (s *ServerGrpc) CrossPaymentRefundRequest(ctx context.Context, rq *pbServer.CrossPaymentRefundReqMessage) (*pbServer.Result, error) {


	log.Println("===== Cross Payment Refund Start =====")

	//from := rq.From
	//to := rq.To
	pn := rq.Pn
	amount := rq.Amount
	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(rq.OriginalMessage, rq.Signature)
        fmt.Println(convertedOriginalMsg, convertedSignatureMsg)

	is_verified := 1// C.ecall_cross_create_all_refund_msg_w(convertedOriginalMsg, convertedSignatureMsg)
	fmt.Println("all confirm msg : ", is_verified)

	//PaymentNum := C.ecall_accept_request_w(&sender[0], &receiver[0], C.uint(amount))
	p, _, paymentInformation, _ := SearchPath(pn, amount, 1, 2)

	go WrapperCrossRefundPayment(int(pn), p, paymentInformation)
	//go WrapperCrossUpdateRequest(pn, p, paymentInformation)

	log.Println("===== Cross Payment Refund End =====")
	return &pbServer.Result{Result: true}, nil
}

func SendCrossAgreementRequest(pn int64, address string, p []string, amount int64, paymentInformation PaymentInformation) {

	fmt.Println("===== SEND CROSS AG REQ START =====")

	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal("GetClientInfo err : ", err)
		return
	}
/*
	fmt.Println("client ip   : ", (*info).IP)
	fmt.Println("client port : ", strconv.Itoa((*info).Port))
*/
	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	
	/*
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}

	fmt.Println("clientAddr : ", clientAddr)
	defer conn.Close()
	*/

	client := pbClient.NewClientClient(connectionForClient[clientAddr])
	if client == nil {
		log.Fatal("client conn err")
		return
	}
	//fmt.Println("client : ", client)

	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	
	fmt.Println("channelSlice : ", channelSlice)
	fmt.Println("amountSlice  : ", amountSlice)
	//fmt.Println("len channelSlice : ", len(channelSlice))
	

	var originalMessage *C.uchar
	var signature *C.uchar

	fmt.Println("===== CREATE AG REQ MSG START IN ENCLAVE =====")
/*
        if &channelSlice[0] != nil {
		fmt.Println("dd")
	}

	if &amountSlice[0] != nil {
		fmt.Println("aa")
	}
*/
	//fmt.Println("????????????????????????")

	//rwMutex.Lock()
	//C.ecall_cross_create_ag_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)
	//rwMutex.Unlock()
	fmt.Println("===== CREATE AG REQ MSG END IN ENCLAVE =====")
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	r, err := client.CrossPaymentPrepareClientRequest(context.Background(), &pbClient.CrossPaymentPrepareReqClientMessage{PaymentNumber: int64(pn), Addr: p, Amount: amount, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println("client AgreementRequest err : ", err)
		return
	}

	//log.Println("R Result : ", r.Result)
	if r.Result {

		agreementOriginalMessage, agreementSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		fmt.Println(agreementOriginalMessage, agreementSignature) 
		//C.ecall_cross_verify_ag_res_msg_w(&([]C.uchar(address)[0]), agreementOriginalMessage, agreementSignature)
		
		//log.Println("is_verified : ", is_verified)

		/*
		rwMutex.Lock()
		prepared[pn]++
		rwMutex.Unlock()
		*/
		ch[pn] <- true
	}
/*
	rwMutex.Lock()
	C.ecall_cross_update_sentagr_list_w(C.uint(pn), &([]C.uchar(address)[0]))
	rwMutex.Unlock()
*/
	fmt.Println("===== SEND CROSS AG REQ END =====")

	return
}

func SendCrossUpdateRequest(pn int64, address string, paymentInformation PaymentInformation) {

	fmt.Println("===== SEND CROSS UD REQ START =====")
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	//log.Println("CrossUpdate Client : ", clientAddr)

	/*
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()
	*/

	client := pbClient.NewClientClient(connectionForClient[clientAddr])
	if client == nil {
		log.Fatal("client conn err")
	}

	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	var originalMessage *C.uchar
	var signature *C.uchar
	fmt.Println(channelSlice, amountSlice)

	//log.Println("===== SendCrossUpdateRequest =====")
	log.Println("===== CREATE UD REQ MSG START IN ENCLAVE =====")
/*
        if &channelSlice[0] != nil {
		fmt.Println("dd")
	}

	if &amountSlice[0] != nil {
		fmt.Println("aa")
	}
*/
	//fmt.Println("????????????????????????")

	//rwMutex.Lock()
	//C.ecall_cross_create_ud_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)
	//rwMutex.Unlock()
	log.Println("===== CREATE UD REQ MSG END IN ENCLAVE =====")

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	rqm := pbClient.CrossPaymentCommitReqClientMessage{ /* convert AgreeRequestsMessage to UpdateRequestsMessage */
		PaymentNumber:   pn,
		OriginalMessage: originalMessageByte,
		Signature:       signatureByte,
	}

	r, err := client.CrossPaymentCommitClientRequest(context.Background(), &rqm)
	if err != nil {
		log.Fatal(err)
		return
	}

//	log.Println("R Result : ", r.GetResult())
	if r.Result {

		updateOriginalMessage, updateSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		fmt.Println(updateOriginalMessage, updateSignature)
		//C.ecall_cross_verify_ud_res_msg_w(&([]C.uchar(address)[0]), updateOriginalMessage, updateSignature)

		/*
		rwMutex.Lock()
		committed[pn]++
		rwMutex.Unlock()
		*/

		ch[pn] <- true
	}

/*
	rwMutex.Lock()
	log.Println("===== Mutex START =====")
	C.ecall_cross_update_sentupt_list_w(C.uint(pn), &([]C.uchar(address))[0])
	log.Println("===== Mutex END =====")
	rwMutex.Unlock()
*/

	fmt.Println("===== SEND CROSS UD REQ START =====")
	return
}

func SendCrossConfirmPayment(pn int, address string, paymentInformation PaymentInformation) {

	fmt.Println("===== SEND CROSS CONFIRM START =====")

	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	/*
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()
	*/

	client := pbClient.NewClientClient(connectionForClient[clientAddr])
	if client == nil {
		log.Fatal("client conn err")
	}

	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	var originalMessage *C.uchar
	var signature *C.uchar
	fmt.Println(channelSlice, amountSlice)
	log.Println("===== CREATE CONFIRM MSG START IN ENCLAVE =====")
	//rwMutex.Lock()
	//C.ecall_cross_create_confirm_msg_w(C.uint(int32(pn)), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)
	//rwMutex.Unlock()
	log.Println("===== CREATE CONFIRM MSG END IN ENCLAVE =====")

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	_, err = client.CrossPaymentConfirmClientRequest(context.Background(), &pbClient.CrossPaymentConfirmReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte}, )
	if err != nil {
		log.Println(err)
		return 
	}

	fmt.Println("===== SEND CROSS CONFIRM END =====")
}

func SendCrossRefundPayment(pn int, address string, paymentInformation PaymentInformation) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)


	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	var originalMessage *C.uchar
	var signature *C.uchar
        fmt.Println(channelSlice, amountSlice)

	//C.ecall_cross_create_refund_msg_w(C.uint(int32(pn)), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	_, err = client.CrossPaymentRefundClientRequest(context.Background(), &pbClient.CrossPaymentRefundReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte}, )
	if err != nil {
		log.Println(err)
	}
}
/*
func SendCrossRefundPayment(pn int, address string) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)

	var originalMessage *C.uchar
	var signature *C.uchar
	C.ecall_cross_create_refund_msg_w(C.uint(int32(pn)), &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	_, err = client.CrossPaymentRefundClientRequest(context.Background(), &pbClient.CrossPaymentRefundReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte}, )
	if err != nil {
		log.Println(err)
	}
}
*/

func WrapperCrossAgreementRequest(pn int64, p []string, amount int64, paymentInformation map[string]PaymentInformation, originalMessageByte []byte, signatureByte []byte) (bool) {

	var AG = AG{}
	AG.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		AG.pn = pn
		AG.address = address
		AG.originalMessageByte = originalMessageByte
		AG.signatureByte = signatureByte
//		fmt.Println(address)
//		fmt.Println(paymentInformation[address])
/*
		paymentInform1 := PaymentInformation{ChannelInform: channelInform1, AmountInform: amountInform1}
		paymentInform2 := PaymentInformation{ChannelInform: channelInform2, AmountInform: amountInform2}
		paymentInform3 := PaymentInformation{ChannelInform: channelInform3, AmountInform: amountInform3}

		paymentInformation := make(map[string]PaymentInformation)
*/
/*
		rwMutex.Lock()
		AG.paymentInformation[address] = paymentInformation[address]
		rwMutex.Unlock()
*/
		wg.Add(1)
		go sendAgreementRequestPool.Invoke(AG)
		//go SendAgreementRequest(pn, address, paymentInformation[address])
	}
/*
	for C.ecall_check_unanimity_w(C.uint(pn), C.int(0)) != 1 {
	}
*/

	for i:= 1; i<=3; i++ {
		var data = <- ch[pn]
		//fmt.Printf("%d AG response %d \n", pn, i)
		if data == true {
			chPrepared[pn]++
		}

		if chPrepared[pn] == 3 {
			break
		}
	}

	//fmt.Println("ALL AG")


/*
	elapsedTime := time.Since(StartTime)
	fmt.Println("****************************************************************")
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)
	ChComplete[pn] <- true
	fmt.Printf("PN SUCCESS : %d \n", pn)
*/

	//var originalMessage *C.uchar// = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	//var signature *C.uchar

/*
	for ; ; {
		result := C.ecall_create_ud_req_msg_temp_w(C.uint(pn), &_sender[0], &_middleMan[0], &_receiver[0] , C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0],  &originalMessage, &signature)

		if result != 9999 {

		} else if result == 9999 {
			break
		}
	}

	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)
*/

//	return true

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

	originalMessageByte, signatureByte = createMsgAndSig(int64(pn), p, paymentInformation, 5)

	originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
	signatureByteArray = append(signatureByteArray, signatureByte)

	for _, address := range p {
//		originalMessageByteArray[i] = make
		//originalMessageByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte
		//signatureByteArray[i] = paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte

		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

/* remove C's address from p */
//	var q []string
//	q = p[0:2]
/*
	for _, address := range q {
		go SendCrossAgreementRequest(pn, address, paymentInformation[address])
	}
*/
/*
	fmt.Println("===== WRAPPER CROSS AG REQ START =====")
	for _, address := range p {
		go SendCrossAgreementRequest(pn, address, p, amount, paymentInformation[address])
	}
*/

/*
	for C.ecall_cross_check_unanimity_w(C.uint(pn), C.int(0)) != 1 {
	}
*/
	// C.ecall_cross_all_prepared_msg_w(C.uint(pn))
//	var originalMessage *C.uchar
//	var signature *C.uchar


	/*
	for {

//		fmt.Printf("****************** PN : %d prepared[PN] :%d NONE ***************\n", pn, prepared[pn])
		if prepared[pn] == 3 {
			break
		}
	}
	*/
/*
	for i:= 1; i<=3; i++ {
		var data = <- ch[pn]
		
		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 3 {
			break
		}
	}

	fmt.Printf("PN : %d [ALARM] ALL USERS PREPARED %d \n", pn, prepared[pn])

	fmt.Println("===== CREATE CROSS ALL PREPARED MSG START IN ENCLAVE =====")
	var originalMessage *C.uchar
	var signature *C.uchar
	//rwMutex.Lock()
	//C.ecall_cross_create_all_prepared_msg_w(C.uint(pn), &originalMessage, &signature)
	//rwMutex.Unlock()
	fmt.Println("===== CREATE CROSS ALL PREPARED MSG END IN ENCLAVE =====")

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
*/
	/*
	connectionForXServer, err := grpc.Dial("141.223.121.164:50009", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()
	*/


	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	if XServer == nil {
		log.Fatal("XServer conn err")
		return false
	}

	XServerContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	_, err := XServer.CrossPaymentPrepared(XServerContext, &pbXServer.CrossPaymentPrepareResMessage{Pn: pn, OriginalMessage: originalMessageByte, Signature: signatureByte, Result: true})
	if err != nil {
		log.Fatal("***** ERROR ***** ", err)
		return false
	}

	//fmt.Printf("PN : %d Result : %t \n", pn, r.GetResult())
	fmt.Printf("********************************* ALL PREPARED MSG %d SENT **************************************** \n", pn)

	fmt.Println("===== WRAPPER CROSS AG REQ END =====")
	//go WrapperCrossUpdateRequest(pn, p, paymentInformation)

	return true
}

func WrapperCrossUpdateRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArray [][]byte, signatureByteArray [][]byte) (bool) {

	//fmt.Println("===== WRAPPER CROSS UD REQ START =====")

	var UD = UD{}
	UD.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = pn
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArray
		UD.signatureByteArray = signatureByteArray

//		fmt.Println(address)
//		fmt.Println(paymentInformation[address])
/*
		paymentInform1 := PaymentInformation{ChannelInform: channelInform1, AmountInform: amountInform1}
		paymentInform2 := PaymentInformation{ChannelInform: channelInform2, AmountInform: amountInform2}
		paymentInform3 := PaymentInformation{ChannelInform: channelInform3, AmountInform: amountInform3}

		paymentInformation := make(map[string]PaymentInformation)
*/
/*
		rwMutex.Lock()
		AG.paymentInformation[address] = paymentInformation[address]
		rwMutex.Unlock()
*/
		wg.Add(1)
		go sendUpdateRequestPool.Invoke(UD)

		//go SendUpdateRequest(pn, address, paymentInformation[address])
	}
/*
	for C.ecall_check_unanimity_w(C.uint(pn), C.int(1)) != 1 {
	}
*/
	for i:= 1; i<=3; i++ {
		var data = <- ch[pn]
		//fmt.Printf("%d UD response %d \n", pn, i)

		if data == true {
			chCommitted[pn]++
		}

		if chCommitted[pn] == 3 {
			break
		}
	}

	return true
/*
	for _, address := range p {
		if(address != "af55ba9376db959fab2af86d565325829b08ea3c4") {
			go SendCrossUpdateRequest(pn, address, paymentInformation[address])
		}
	}
*/
	//fmt.Println("pn : ", pn)
	/*
	for C.ecall_cross_check_unanimity_w(C.uint(pn), C.int(1)) != 1 {
	}
	*/

	//committed[pn]++

	/*
	for {
//		fmt.Printf("****************** PN : %d committed[PN] :%d PREPARE ***************\n", pn, committed[pn])
		if committed[pn] == 3 {
			break
		}
	}
	*/
/*
	for i:= 1; i<=3; i++ {
		var data = <- ch[pn]
		
		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 6 {
			break
		}
	}
*/
	fmt.Println("[ALARM] ALL USERS COMMITTED")

	fmt.Println("===== CREATE CROSS ALL COMMITTED MSG START IN ENCLAVE =====")
	var originalMessage *C.uchar
	var signature *C.uchar
	//rwMutex.Lock()
	//C.ecall_cross_create_all_committed_msg_w(C.uint(pn), &originalMessage, &signature)
	//rwMutex.Unlock()
	fmt.Println("===== CREATE CROSS ALL COMMITTED MSG END IN ENCLAVE =====")
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	//originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	/*
	connectionForXServer, err := grpc.Dial("141.223.121.164:50009", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()
	*/

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	if XServer == nil {
		log.Fatal("XServer conn err")
		return false
	}

	XServerContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()

	_, err := XServer.CrossPaymentCommitted(XServerContext, &pbXServer.CrossPaymentCommitResMessage{Pn: pn, OriginalMessage: originalMessageByte, Signature: signatureByte, Result: true})
	if err != nil {
		log.Fatal("***** ERROR ***** ", err)
		return false
	}

	//fmt.Printf("PN : %d Result : %t \n", pn, r.GetResult())

	//go WrapperCrossConfirmPayment(int(pn), p)
        fmt.Println("===== WRAPPER CROSS UD REQ END =====")
	return true

}

func WrapperCrossConfirmPayment(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArray [][]byte, signatureByteArray [][]byte) {
	/* update payment's status */
	//C.ecall_cross_update_payment_status_to_success_w(C.uint(pn))

	var UD = UD{}
	//AG.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = int64(pn)
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArray
		UD.signatureByteArray = signatureByteArray

		wg.Add(1)
		go sendConfirmPaymentPool.Invoke(UD)
		//go SendConfirmPayment(pn, address)
	}
/*
	for _, address := range p {
		go SendCrossConfirmPayment(pn, address, paymentInformation[address])
	}
*/
	//fmt.Println("SENT CONFIRMATION TO ALL USERS")
}

func WrapperCrossRefundPayment(pn int, p []string, paymentInformation map[string]PaymentInformation) {
	/* update payment's status */
	//C.ecall_cross_update_payment_status_to_success_w(C.uint(pn))

	for _, address := range p {
		go SendCrossRefundPayment(pn, address, paymentInformation[address])
	}
	fmt.Println("SENT REFUND TO ALL USERS")
}
/*
func WrapperCrossRefundPayment(pn int, p []string) {
	//C.ecall_cross_update_payment_status_to_success_w(C.uint(pn))

	for _, address := range p {
		go SendCrossRefundPayment(pn, address)
	}
	fmt.Println("REFUND MSG TO ALL USERS")
}
*/

func ChanCreate() {

	if chanCreateCheck == 0{
		var i = 0
		for i = range ch {
			ch[i] = make(chan bool)
			ChComplete[i] = make(chan bool)
		}
		fmt.Printf("%d ChanCreate! \n", i)
		i = 0
		for i = range usingChannelIds {
			usingChannelIds[i] = make(chan bool)
		}

		i = 0
		for i = range firstReq {
			firstReq[i] = true
		}
	} else {
		return
	}

	chanCreateCheck = 1
}

func GrpcConnection() {
/*
	tempConnectionForXServer, err := grpc.Dial("141.223.121.164:50009", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	connectionForXServer = tempConnectionForXServer

        tempConn := make(map[string]*grpc.ClientConn)
	tempConn["141.223.121.167:50001"], err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.168:50002"], err = grpc.Dial("141.223.121.168:50002", grpc.WithInsecure())
	if err != nil {
                log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.251:50003"], err = grpc.Dial("141.223.121.251:50003", grpc.WithInsecure())
	if err != nil {
                log.Fatal("conn err : ", err)
		return
	}

	connectionForClient = tempConn
*/

	var tempConnC1 [1000]*grpc.ClientConn// make(map[int]*grpc.ClientConn)
	var tempConnC2 [1000]*grpc.ClientConn
	var tempConnC3 [1000]*grpc.ClientConn
	var tempConnC4 [1000]*grpc.ClientConn
	var tempConnC5 [1000]*grpc.ClientConn
	var tempConnC6 [1000]*grpc.ClientConn

	for i:=0; i<1000; i++ {

		//              tempConn := []*grpc.ClientConn// make(map[int]*grpc.ClientConn)
		//              tempClient1[i] = tempConn

		tempConnC1[i], err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())
		if err != nil {
			log.Fatal("conn err ", err)
		}

		tempConnC2[i], err = grpc.Dial("141.223.121.168:50002", grpc.WithInsecure())
		tempConnC3[i], err = grpc.Dial("141.223.121.251:50003", grpc.WithInsecure())
		tempConnC4[i], err = grpc.Dial("141.223.121.165:50001", grpc.WithInsecure())
		tempConnC5[i], err = grpc.Dial("141.223.121.166:50002", grpc.WithInsecure())
		tempConnC6[i], err = grpc.Dial("141.223.121.169:50003", grpc.WithInsecure())
	}

	connClient["141.223.121.167:50001"] = tempConnC1
	connClient["141.223.121.168:50002"] = tempConnC2
	connClient["141.223.121.251:50003"] = tempConnC3
	connClient["141.223.121.165:50001"] = tempConnC4
	connClient["141.223.121.166:50002"] = tempConnC5
	connClient["141.223.121.169:50003"] = tempConnC6

	var i = 0
	for i=0; i<100; i++ {
		Client[i] = pbServer.NewServerClient(connection)
		ClientContext[i], _ = context.WithTimeout(context.Background(), time.Second*180)
	}

	fmt.Println("Grpc Connection !!")
}
/*
func GrPoolCreation() {

	sendAgreementRequestPool, _ = ants.NewPoolWithFunc(10, func(i interface{}) {
	//	myFunc(i)
	//	wg.Done()
	})
	//defer p.Release()
	// Submit tasks one by one.
	//for i := 0; i < runTimes; i++ {
	//	wg.Add(1)
	//	_ = p.Invoke(int32(i))
	//}
}
*/

func GetClientInfo() {

/*
	info, _ := repository.GetClientInfo("f55ba9376db959fab2af86d565325829b08ea3c4")
	Addr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	fmt.Println("Addr >>", Addr)

	clientAddr["f55ba9376db959fab2af86d565325829b08ea3c4"] = Addr

	info, err = repository.GetClientInfo("c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")
	Addr = (*info).IP + ":" + strconv.Itoa((*info).Port)
	//Addr = "141.223.121.168:50002"

	clientAddr["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = Addr

	info, err = repository.GetClientInfo("70603f1189790fcd0fd753a7fef464bdc2c2ad36")
	Addr = (*info).IP + ":" + strconv.Itoa((*info).Port)
	//Addr = "141.223.121.169:50003"

	clientAddr["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = Addr
*/
//	info, err := repository.GetClientInfo(address)

//	fmt.Println("client ip   : ", (*info).IP)
//	fmt.Println("client port : ", strconv.Itoa((*info).Port))


	p = append(p, "f55ba9376db959fab2af86d565325829b08ea3c4")
        p = append(p, "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")
	p = append(p, "70603f1189790fcd0fd753a7fef464bdc2c2ad36")

	p2 = append(p2, "f4444529d6221122d1712c52623ba119a60609e3")
	p2 = append(p2, "d95da40bbd2001abf1a558c0b1dffd75940b8fd9")
	p2 = append(p2, "73d8e5475278f7593b5293beaa45fb53f34c9ad2")

	clientAddr["f55ba9376db959fab2af86d565325829b08ea3c4"] = "141.223.121.167:50001"
	clientAddr["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = "141.223.121.168:50002"
	clientAddr["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = "141.223.121.251:50003"

	clientAddr["f4444529d6221122d1712c52623ba119a60609e3"] = "141.223.121.165:50001"
	clientAddr["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = "141.223.121.166:50002"
	clientAddr["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = "141.223.121.169:50003"

	addrToPubKey["f55ba9376db959fab2af86d565325829b08ea3c4"] = "04c8f607a13d4cee66afcd652f08c80d04ac4198e987ff9c728c2baf70c63c8d"
	addrToPubKey["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = "0451f651ffe3d92494082145398fc906dd4bcbc1311e731272519eccf99878b6"
	addrToPubKey["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = "042c93312fad479d5f1bcea4be26fb3eae7024185d9da0cb540b0bf85a46a7c5"

	addrToPubKey["f4444529d6221122d1712c52623ba119a60609e3"] = "04e533581de6901d744ed8b811ffbb00b2f012c96758cde0d0dc850070c985ff"
	addrToPubKey["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = "04e29aa0212e58dc2da435d0a658310120bc4abfeed3c82143b3b73c829624c7"
	addrToPubKey["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = "045502868ff7878a73a7fdae4ac06a70fc137565f79e27a814f8dd8e1b4dd698"

	fmt.Println("Client Addr initialization !!")
}

func checkChannelIds(pn int64) {

	//fmt.Printf("channelId %d waiting start for pn %d\n", pnToChannelId[pn], pn)
	<-usingChannelIds[pnToChannelId[pn]]
	//fmt.Printf("channelId %d waiting end for pn %d... \n", pnToChannelId[pn], pn)
}

func inputChannelIds(pn int64) {//, paymentInfo PaymentInformation) {

	//fmt.Printf("channelId %d inputing start... for pn %d \n", pnToChannelId[pn], pn)
	//paymentInfo := paymentInformation["f55ba9376db959fab2af86d565325829b08ea3c4"]
	usingChannelIds[pnToChannelId[pn]/*paymentInfo.ChannelInform[0]*/] <- true
	//fmt.Printf("channelId %d inputing end for pn %d \n", pnToChannelId[pn], pn)
}

func createMsgAndSig(pn int64, p []string, paymentInformation map[string]PaymentInformation, messageType uint) ([]byte, []byte) {

	var originalMessage *C.uchar// = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	var __signature[65] C.uchar
	var signature *C.uchar

	var Message = Message{}
	Message.messageType = C.uint(messageType) // AG_REQ

	//Message.channel_id = 1
	//Message.amount = 1
	//Message.counter =0

	Message.payment_num = C.uint(pn)
	//var party = "f55ba9376db959fab2af86d565325829b08ea3c4"

	rwMutex.Lock()
	paymentInformation1 := paymentInformation[p[0]]
	paymentInformation2 := paymentInformation[p[1]]
	paymentInformation3 := paymentInformation[p[2]]
	rwMutex.Unlock()

	var channelSlice [3][]C.uint
	var amountSlice [3][]C.int

	channelSlice[0] = paymentInformation1.ChannelInform
	amountSlice[0] = paymentInformation1.AmountInform

	channelSlice[1] = paymentInformation2.ChannelInform
	amountSlice[1] = paymentInformation2.AmountInform

	channelSlice[2] = paymentInformation3.ChannelInform
        amountSlice[2] = paymentInformation3.AmountInform

	/*
	var Participant2 = Participant{}
	var Participant3 = Participant{}
	*/

	for i, _ := range p {

		var Participant = Participant{}

		for j := 0; j < 40; j++ {
			Participant.party[j] = C.uchar(p[i][j])
		}

		Participant.payment_size = C.uint(len(channelSlice[i]))

		for j := 0; j < int(Participant.payment_size); j++ {
			Participant.channel_ids[j] = channelSlice[i][j]
			Participant.payment_amount[j] = amountSlice[i][j]
		}

		Message.participant[i] = Participant
	}

/*
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := elliptic.Marshal(secp256k1.S256(), key.X, key.Y)
	fmt.Println("pubkey : ", pubkey)
	for i := 0; i < 65; i++ {
		fmt.Printf("%02x", pubkey[i])
	}
	seckey := make([]byte, 32)
	blob := key.D.Bytes()
	copy(seckey[32-len(blob):], blob)
	fmt.Println("seckey : ", seckey)
	for i := 0; i < 32; i++ {
		fmt.Printf("%02x", seckey[i])
	}
*/

	originalMessage = (*C.uchar)(unsafe.Pointer(&Message))
	signature = (*C.uchar)(unsafe.Pointer(&__signature))

	originalMessageByte, _ := convertPointerToByte(originalMessage, signature)
//	fmt.Println("original sig : ", signatureByte)

	messageHash := crypto.Keccak256(originalMessageByte) // or messageHash := sha256.Sum256([]byte(originalMessageByte))

//	messageHash := chainhash.HashB([]byte(originalMessageByte))
/*	messageHash := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, messageHash); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
*/
	_signature, err := secp256k1.Sign(messageHash[:], seckey)
	//fmt.Println("signature : ", _signature)
	if err != nil {
		fmt.Println("error ", err)
		return nil, nil
	}
/*
	var b = int(_signature[32])
	if b < 0 {
		fmt.Println("highest bit is negative: %d", b)
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		fmt.Println("highest bit: %d bit >> 7: %d", b, b>>7)
	}
	if (b & 0x80) == 0x80 {
		fmt.Println("highest bit: %d bit & 0x80: %d", b, b&0x80)
	}

	if len(pubkey) != 65 {
		fmt.Println("pubkey length mismatch: want: 65 have: %d", len(pubkey))
	}
	if len(seckey) != 32 {
		fmt.Println("seckey length mismatch: want: 32 have: %d", len(seckey))
	}
	if len(_signature) != 65 {
		fmt.Println("sig length mismatch: want: 65 have: %d", len(_signature))
	}
	recid := int(_signature[64])
	if recid > 4 || recid < 0 {
		fmt.Println("sig recid mismatch: want: within 0 to 4 have: %d", int(_signature[64]))
	}
*/
/*	err = secp256k1.checkSignature(_signature)
	if err != nil {
		fmt.Println(err)
		return &pbServer.Result{Result: false}, nil
	}
*/
	//verified := secp256k1.VerifySignature(pubkey, messageHash, _signature)
	//verified := signature.Verify(messageHash, pubkey)
	//fmt.Printf("Signature Verified? %v\n", verified)

	//_signature, err := privKey.Sign(messageHash)

	originalMessage = (*C.uchar)(unsafe.Pointer(&Message))
	signature = (*C.uchar)(unsafe.Pointer(&_signature))


	//fmt.Println("msg : ", originalMessage)
	//fmt.Println("sig : ", signature)
	originalMessageByte, _ = convertPointerToByte(originalMessage, signature)

	//fmt.Println("msg : ", originalMessageByte)
	//fmt.Println("sig : ", signatureByte)

	//verified = secp256k1.VerifySignature(pubkey, messageHash, _signature)
	//verified := signature.Verify(messageHash, pubkey)
	//fmt.Printf("Signature Verified? %v\n", verified)


	return originalMessageByte, _signature
}

func createCrossMsgAndSig(pn int64, p []string, paymentInformation map[string]PaymentInformation, messageType uint, serverIndex uint) ([]byte, []byte) {

	var originalMessage *C.uchar// = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	var __signature[65] C.uchar
	var signature *C.uchar

	var Cross_Message = Cross_Message{}
	Cross_Message.cross_messageType = C.uint(messageType) // AG_REQ
	Cross_Message.cross_paymentServer = C.uint(serverIndex)
	//Message.channel_id = 1
	//Message.amount = 1
	//Message.counter =0

	Cross_Message.payment_num = C.uint(pn)
	//var party = "f55ba9376db959fab2af86d565325829b08ea3c4"

	originalMessage = (*C.uchar)(unsafe.Pointer(&Cross_Message))
	signature = (*C.uchar)(unsafe.Pointer(&__signature))

	originalMessageByte, _ := convertPointerToByte(originalMessage, signature)
//	fmt.Println("original sig : ", signatureByte)

	messageHash := chainhash.HashB([]byte(originalMessageByte))
	_signature, err := secp256k1.Sign(messageHash, seckey)
	//fmt.Println("signature : ", _signature)
	if err != nil {
		fmt.Println("error ", err)
		return nil, nil
	}
	originalMessage = (*C.uchar)(unsafe.Pointer(&Cross_Message))
	signature = (*C.uchar)(unsafe.Pointer(&_signature))

	originalMessageByte, _ = convertPointerToByte(originalMessage, signature)

	return originalMessageByte, _signature
}
