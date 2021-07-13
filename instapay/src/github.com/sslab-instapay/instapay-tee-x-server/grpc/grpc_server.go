package grpc

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "../app.h"
*/
import "C"

import (
	"net"
	"log"
	"fmt"
	"os"
	"sync"
	"context"
	"strconv"
	"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/config"
	"time"
	"unsafe"
	"reflect"

	"github.com/panjf2000/ants"
	//"github.com/sslab-instapay/instapay-tee-x-server/repository"
	pbServer "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	pbClient "github.com/sslab-instapay/instapay-tee-x-server/proto/client"
	pbXServer"github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	//"unsafe"
	//"reflect"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

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

var checkChFirstOrNot [10000]int
var paymentNumToChId [500000]int

var prepareMsgCreation [500000]chan bool
var prepareMsgSuccess [100000]int
var commitMsgCreation [500000]chan bool
var commitMsgSuccess [100000]int
var confirmMsgCreation [500000]chan bool
var confirmMsgSuccess [100000]int

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
	pbXServer.UnimplementedCross_ServerServer
}

var connClient = make(map[string][1000]*grpc.ClientConn) //map[int]*grpc.ClientConn)

var Cross_connection, err = grpc.Dial("141.223.121.164:50009", grpc.WithInsecure())
var Cross_Client [100]pbXServer.Cross_ServerClient
var Cross_ClientContext [100]context.Context

var connection, _ = grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
var Client [100]pbServer.ServerClient //= pbServer.NewServerClient(connection)
var ClientContext [100]context.Context

var connectionForServer = make(map[string]*grpc.ClientConn)

var Ch [500000]chan bool
var ChComplete [500000]chan bool
//var Ch chan bool = make(chan bool)
//var Ch = make(map[int](chan bool), 3)
var chprepared [100000]int
var chCommitted [100000]int
var chConfirmed [100000]int

var chanCreateCheck = 0

//var prepared [1000000]int
//var committed [1000000]int
//var timer [1000000]int

var rwMutex = new(sync.RWMutex)
var StartTime time.Time

var ChainFrom []string
var ChainTo   []string
var ChainVal  []int64

//var StartTime1 time.Time
//var StartTime2 time.Time
//var StartTime3 time.Time

var channelId = 1
var PaymentRequest [100000]Payment

type PaymentInformation struct {
	ChannelInform []C.uint
	AmountInform  []C.int
}

var paymentInformation = make(map[string]PaymentInformation)
var p []string

var _paymentInformation = make(map[string]PaymentInformation)
var p2 []string

//info, _ := repository.GetClientInfo("f55ba9376db959fab2af86d565325829b08ea3c4")
var clientAddr = make(map[string]string)
var connectionForClient = make(map[string]*grpc.ClientConn)

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

var wg sync.WaitGroup

var sendCrossPaymentPrepareRequestPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {
	SendCrossPaymentPrepareRequest(i)
	wg.Done()
})

var sendCrossPaymentCommitRequestPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {
	SendCrossPaymentCommitRequest(i)
	wg.Done()
})

var sendCrossPaymentConfirmRequestPool, _ = ants.NewPoolWithFunc(500000, func(i interface{}) {
	SendCrossPaymentConfirmRequest(i)
	wg.Done()
})

func SendCrossPaymentPrepareRequest(i interface{}) {

	pn := i.(AG).pn
	address := i.(AG).address
	originalMessageByte := i.(AG).originalMessageByte
	signatureByte := i.(AG).signatureByte

//	client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])
//	var connection, err = grpc.Dial(clientAddr[address], grpc.WithInsecure())
//	client := pbClient.NewClientClient(connection)
	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%10])
//	client1Context, cancel := context.WithTimeout(context.Background(), time.Second*180)
//	defer cancel()

	if client == nil {
		log.Fatal("client conn err")
	}
/*
	r, err := client.AgreementRequest(context.Background(), &pbClient.AgreeRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})
*/
	r, err := client.CrossPaymentPrepareClientRequest(context.Background(), &pbClient.CrossPaymentPrepareReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})

	if err != nil {
		log.Println("client AgreementRequest err : ", err, clientAddr[address])
	}

	if r.Result{

		agreementOriginalMessage, signature := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)

		for ; ; {
			result := C.ecall_cross_verify_all_prepared_res_msg_temp_w(agreementOriginalMessage, signature)

			if result == 9999 {
				break
			}
		}

		var clientPrepareMsgRes = AG{}
		clientPrepareMsgRes.originalMessageByte = r.OriginalMessage
		clientPrepareMsgRes.signatureByte = r.Signature

		rwMutex.Lock()
		paymentPrepareMsgRes[strconv.FormatInt(pn, 10)+address] = clientPrepareMsgRes
		rwMutex.Unlock()
		Ch[pn] <- true
	}

		//secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)
}

func SendCrossPaymentCommitRequest(i interface{}) {

	pn := i.(UD).pn
	address := i.(UD).address
	originalMessageByteArray := i.(UD).originalMessageByteArray
	signatureByteArray := i.(UD).signatureByteArray

//	client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])
	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%10])

	if client == nil {
		log.Fatal("client conn err")
	}

/*
	r, err := client.UpdateRequest(context.Background(), &pbClient.UpdateRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray})
*/
	r, err := client.CrossPaymentCommitClientRequest(context.Background(), &pbClient.CrossPaymentCommitReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray})

	if err != nil {
		log.Println("client Commit Request err : ", err, clientAddr[address])
	}


	if r.Result {

		updateOriginalMessage, signature := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)
		//C.ecall_cross_verify_all_committed_res_msg_temp_w(updateOriginalMessage, signature)
		for ; ; {
			result := C.ecall_cross_verify_all_committed_res_msg_temp_w(updateOriginalMessage, signature)

			if result == 9999 {
				break
			}
		}

		var clientCommitMsgRes = AG{}
		clientCommitMsgRes.originalMessageByte = r.OriginalMessage
		clientCommitMsgRes.signatureByte = r.Signature

		rwMutex.Lock()
		paymentCommitMsgRes[strconv.FormatInt(pn, 10)+address] = clientCommitMsgRes
		rwMutex.Unlock()
		Ch[pn] <- true

	}


		//secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)
	return
}

func SendCrossPaymentConfirmRequest(i interface{}) {

	pn := i.(UD).pn
	address := i.(UD).address
	originalMessageByteArray := i.(UD).originalMessageByteArray
	signatureByteArray := i.(UD).signatureByteArray

	//client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])

	client := pbClient.NewClientClient(connClient[clientAddr[address]][int(pn)%10])
	if client == nil {
		log.Fatal("client conn err")
	}

	_, err := client.CrossPaymentConfirmClientRequest(context.Background(), &pbClient.CrossPaymentConfirmReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray})

	if err != nil {
		log.Println("client Confirm Request err : ", err)
	}

	Ch[pn] <- true
		//secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)
	return
}

func StartGrpcServer() {

	ChanCreate()
	GrpcConnection()
	GetClientInfo()

	//////
//	StartTime = time.Now()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	StartTime = time.Now()

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x\n", sig)
	elapsedTime1 := time.Since(StartTime)
	fmt.Printf("execution time : %s \n", elapsedTime1)

	//StartTime = time.Now()
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
	fmt.Println("signature verified:", valid)
	elapsedTime := time.Since(StartTime)
	fmt.Printf("execution time : %s \n", elapsedTime)
	//////

	grpcPort, err := strconv.Atoi(os.Getenv("grpc_port"))
	if err != nil {
		log.Fatal(err)
	}

	log.Println("grpcPort : ", grpcPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pbServer.RegisterServerServer(grpcServer, &ServerGrpc{})
	pbXServer.RegisterCross_ServerServer(grpcServer, &ServerGrpc{})

	grpcServer.Serve(lis)
}
/*
func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	log.Println("----- convertByteToPointer Server Start -----")
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

	return cOriginalMsg, cSignature
}

func convertPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(44),
		Cap:  int(44),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 44; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

	return returnMsg, returnSignature
}

type PaymentInformation struct {
	ChannelInform []C.uint
	AmountInform  []C.int
}
*/
/*
 instpay 3.0

*/

func SearchPath(pn int64, amount int64, firstTempChId int, secondTempChId int) ([]string, []string, map[string]PaymentInformation, map[string]PaymentInformation) {

/*
	p = append(p, "f55ba9376db959fab2af86d565325829b08ea3c4")
	p = append(p, "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")
	p = append(p, "70603f1189790fcd0fd753a7fef464bdc2c2ad36")
*/
	var channelInform1, channelInform2, channelInform3 []C.uint
	var amountInform1, amountInform2, amountInform3 []C.int

	channelInform1 = append(channelInform1, C.uint(firstTempChId))
	channelInform2 = append(channelInform2, C.uint(firstTempChId))
	//      channelId++
	channelInform2 = append(channelInform2, C.uint(secondTempChId))
	channelInform3 = append(channelInform3, C.uint(secondTempChId))
	//      channelId++
	//      rwMutex.Unlock()
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

//         log.Println("===== SearchPath End =====")
	 return p, p2, paymentInformation, _paymentInformation
}

func (s *ServerGrpc) CrossPaymentRequest(ctx context.Context, rs *pbXServer.CrossPaymentMessage) (*pbXServer.CrossResult, error) {


//	C.ecall_cross_verify_all_prepared_res_msg_temp_w(nil, nil)

/*
	sendera := []C.uchar("sender")
	receivera := []C.uchar("receiver")

	for ; ; {
		result := C.ecall_accept_request_w(&sendera[0], &receivera[0], 1)
		if result != 999999 {
			break
		}
	}

	return &pbXServer.CrossResult{Result: true}, nil
*/
	var originalMessageForPrepare *C.uchar
        var signatureForPrepare *C.uchar
	var originalMessageForPrepare2 *C.uchar
        var signatureForPrepare2 *C.uchar

	var originalMessageForCommit *C.uchar
        var signatureForCommit *C.uchar
	var originalMessageForCommit2 *C.uchar
        var signatureForCommit2 *C.uchar

	var originalMessageForConfirm *C.uchar
        var signatureForConfirm *C.uchar
	var originalMessageForConfirm2 *C.uchar
        var signatureForConfirm2 *C.uchar

	rwMutex.Lock()
	firstTempChId := channelId
	secondTempChId := channelId+1

	channelId+=2
	if channelId > 4500 {
		channelId = 1
	}

	rwMutex.Unlock()
/*
	if checkChFirstOrNot[paymentNumToChId[rs.Pn]] == 0 {	// if channel ID is used first,
		checkChFirstOrNot[paymentNumToChId[rs.Pn]] = 1
	} else {
		if <-ChComplete[paymentNumToChId[rs.Pn]] == true {} // else, wait
	}
*/
	p, p2, paymentInformation, _paymentInformation = SearchPath(int64(rs.Pn), 1, firstTempChId, secondTempChId)

	chain1Sender := []C.uchar(rs.ChainFrom[0])
	chain1Receiver := []C.uchar(rs.ChainTo[0])
	chain1MiddleMan := []C.uchar("c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")

	chain2Sender := []C.uchar(rs.ChainFrom[1])
	chain2Receiver := []C.uchar(rs.ChainTo[1])
	chain2MiddleMan := []C.uchar("d95da40bbd2001abf1a558c0b1dffd75940b8fd9")

	for ; ; {
		PaymentNum := C.ecall_cross_accept_request_w(
			&chain1Sender[0],
			&chain1MiddleMan[0],
			&chain1Receiver[0],
			C.uint(1),
			&chain2Sender[0],
			&chain2MiddleMan[0],
			&chain2Receiver[0],
			C.uint(1),
			nil,
			nil,
			nil,
			C.uint(rs.Pn))

			if PaymentNum != 999999 {
				break
			}
	}

//	return &pbXServer.CrossResult{Result: true}, nil

	sender := []C.uchar(p[0])
	middleMan := []C.uchar(p[1])
	receiver := []C.uchar(p[2])

	sender2 := []C.uchar(p2[0])
	middleMan2 := []C.uchar(p2[1])
	receiver2 := []C.uchar(p2[2])

	rwMutex.Lock()
	paymentInformation1 := paymentInformation[p[0]]
	paymentInformation2 := paymentInformation[p[1]]
	paymentInformation3 := paymentInformation[p[2]]
	rwMutex.Unlock()
/*
	_paymentInformation1 := _paymentInformation[p2[0]]
	_paymentInformation2 := _paymentInformation[p2[1]]
	_paymentInformation3 := _paymentInformation[p2[2]]
*/	

/*	var channelSlice [3][]C.uint
	var amountSlice [3][]C.int
*/
	channelSlice1 := paymentInformation1.ChannelInform
	amountSlice1 := paymentInformation1.AmountInform

	channelSlice2 := paymentInformation2.ChannelInform
	amountSlice2:= paymentInformation2.AmountInform

	channelSlice3 := paymentInformation3.ChannelInform
	amountSlice3 := paymentInformation3.AmountInform
/*
	_channelSlice1 := _paymentInformation1.ChannelInform
	_amountSlice1 := _paymentInformation1.AmountInform

	_channelSlice2 := _paymentInformation2.ChannelInform
	_amountSlice2:= _paymentInformation2.AmountInform

	_channelSlice3 := _paymentInformation3.ChannelInform
	_amountSlice3 := _paymentInformation3.AmountInform
*/

//	st := time.Now()
	go func(){
		for ; ; {
			result := C.ecall_cross_create_all_prepare_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForPrepare, &signatureForPrepare)

			if result == 9999 {
				prepareMsgCreation[rs.Pn] <- true
				break
			} else {
				C.free(unsafe.Pointer(originalMessageForPrepare))
				C.free(unsafe.Pointer(signatureForPrepare))
			}
		}
	}()

	go func() {

		for ; ; {
			result := C.ecall_cross_create_all_prepare_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForPrepare2, &signatureForPrepare2)
			if result == 9999 {
				prepareMsgCreation[rs.Pn] <- true
				break
			} else {
				C.free(unsafe.Pointer(originalMessageForPrepare2))
				C.free(unsafe.Pointer(signatureForPrepare2))
			}
		}
	}()

	for i:=1; ; i++ {
		if <-prepareMsgCreation[rs.Pn] == true {
			prepareMsgSuccess[rs.Pn]++
		}

		if prepareMsgSuccess[rs.Pn] == 2 {
			break
		}
	}


        originalMessageByteForPrepare, signatureByteForPrepare := convertPointerToByte(originalMessageForPrepare, signatureForPrepare)
        originalMessageByteForPrepare2, signatureByteForPrepare2 := convertPointerToByte(originalMessageForPrepare2, signatureForPrepare2)


/*	originalMessageByteForPrepare := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 102, 53, 53, 98, 97, 57, 51, 55, 54, 100, 98, 57, 53, 57, 102, 97, 98, 50, 97, 102, 56, 54, 100, 53, 54, 53, 51, 50, 53, 56, 50, 57, 98, 48, 56, 101, 97, 51, 99, 52, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 99, 54, 48, 102, 54, 52, 48, 99, 52, 53, 48, 53, 100, 49, 53, 98, 57, 55, 50, 101, 54, 102, 99, 50, 97, 50, 97, 55, 99, 98, 97, 48, 57, 100, 48, 53, 100, 57, 102, 55, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 55, 48, 54, 48, 51, 102, 49, 49, 56, 57, 55, 57, 48, 102, 99, 100, 48, 102, 100, 55, 53, 51, 97, 55, 102, 101, 102, 52, 54, 52, 98, 100, 99, 50, 99, 50, 97, 100, 51, 54, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	signatureByteForPrepare := []byte{243, 100, 136, 27, 252, 100, 231, 160, 29, 187, 97, 104, 191, 235, 65, 49, 121, 91, 150, 220, 16, 110, 203, 56, 89, 117, 30, 110, 117, 51, 154, 249, 102, 236, 31, 140, 199, 245, 195, 51, 28, 25, 30, 193, 61, 198, 129, 83, 141, 78, 81, 110, 92, 203, 124, 59, 80, 137, 152, 138, 89, 13, 16, 238, 1}
*/

	go WrapperCrossPaymentPrepareRequest(rs.Pn, p, paymentInformation, originalMessageByteForPrepare, signatureByteForPrepare)

	go WrapperCrossPaymentPrepareRequest(rs.Pn, p2, _paymentInformation, originalMessageByteForPrepare2, signatureByteForPrepare2)

	for i:= 1; ; i++ {

		if <-Ch[int(rs.Pn)] == true {
			chprepared[rs.Pn]++
		}

		if chprepared[rs.Pn] == 6 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}

	}

//	fmt.Println("END")
//	return &pbXServer.CrossResult{Result: true}, nil

	go func() {
		for ; ; {
			result := C.ecall_cross_create_all_commit_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForCommit, &signatureForCommit)

			if result == 9999 {
				commitMsgCreation[rs.Pn] <- true
				break
			} else {
				C.free(unsafe.Pointer(originalMessageForCommit))
				C.free(unsafe.Pointer(signatureForCommit))
			}
		}
	}()

	go func() {
		for ; ; {
			result := C.ecall_cross_create_all_commit_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForCommit2, &signatureForCommit2)
			if result == 9999 {
				commitMsgCreation[rs.Pn] <- true
				break
			} else {
				C.free(unsafe.Pointer(originalMessageForCommit2))
				C.free(unsafe.Pointer(signatureForCommit2))
			}
		}
	}()

	for i:=1; ; i++ {
		if <-commitMsgCreation[rs.Pn] == true {
			commitMsgSuccess[rs.Pn]++
		}

		if commitMsgSuccess[rs.Pn] == 2 {
			break
		}
	}


	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte
//	originalMessageByteArray := make([][]byte, 4)
//	signatureByteArray := make([][]byte, 4)

	originalMessageByteForCommit, signatureByteForCommit := convertPointerToByte(originalMessageForCommit, signatureForCommit)

	originalMessageByteArray = append(originalMessageByteArray, originalMessageByteForCommit)
	signatureByteArray = append(signatureByteArray, signatureByteForCommit)
/*
	originalMessageByteArray[0] = originalMessageByteForCommit
	signatureByteArray[0] = signatureByteForCommit

	for i, address := range p {
		rwMutex.Lock()
		originalMessageByteArray[i+1] = paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte
		signatureByteArray[i+1] = paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte
		rwMutex.Unlock()
	}
*/

	for _, address := range p {
		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}


	var originalMessageByteArray2 [][]byte
	var signatureByteArray2 [][]byte

//	originalMessageByteArray2 := make([][]byte, 4)
//	signatureByteArray2 := make([][]byte, 4)

	originalMessageByteForCommit2, signatureByteForCommit2 := convertPointerToByte(originalMessageForCommit2, signatureForCommit2)


	originalMessageByteArray2 = append(originalMessageByteArray2, originalMessageByteForCommit2)
	signatureByteArray2 = append(signatureByteArray2, signatureByteForCommit2)

	for _, address := range p2 {
		rwMutex.Lock()
		originalMessageByteArray2 = append(originalMessageByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArray2 = append(signatureByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}


	go WrapperCrossPaymentCommitRequest(rs.Pn, p, paymentInformation, originalMessageByteArray, signatureByteArray)

	go WrapperCrossPaymentCommitRequest(rs.Pn, p2, _paymentInformation, originalMessageByteArray2, signatureByteArray2)

	for i:= 1; ; i++ {

		if <-Ch[int(rs.Pn)] == true {
			chCommitted[rs.Pn]++
		}

		if chCommitted[rs.Pn] == 6 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}


//	fmt.Println("END!")
//	return &pbXServer.CrossResult{Result: true}, nil


	go func() {
		for ; ; {
			result := C.ecall_cross_create_all_confirm_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForConfirm, &signatureForConfirm)

			if result == 9999 {
				confirmMsgCreation[rs.Pn] <- true
				break
			} else {

				C.free(unsafe.Pointer(originalMessageForConfirm))
				C.free(unsafe.Pointer(signatureForConfirm))
			}
		}
	}()

	go func() {
		for ; ; {
			result := C.ecall_cross_create_all_confirm_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForConfirm2, &signatureForConfirm2)
			if result == 9999 {
				confirmMsgCreation[rs.Pn] <- true
				break
			} else {
				C.free(unsafe.Pointer(originalMessageForConfirm2))
				C.free(unsafe.Pointer(signatureForConfirm2))
			}
		}
	}()

	for i:=1; ; i++ {
		if <-confirmMsgCreation[rs.Pn] == true {
			confirmMsgSuccess[rs.Pn]++
		}

		if confirmMsgSuccess[rs.Pn] == 2 {
			break
		}
	}

	var originalMessageByteArrayForConfirm [][]byte
	var signatureByteArrayForConfirm [][]byte

	originalMessageByteForConfirm, signatureByteForConfirm := convertPointerToByte(originalMessageForConfirm, signatureForConfirm)
	originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, originalMessageByteForConfirm)
	signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, signatureByteForConfirm)

	for _, address := range p {
		rwMutex.Lock()
		originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}


	var originalMessageByteArrayForConfirm2 [][]byte
	var signatureByteArrayForConfirm2 [][]byte

	originalMessageByteForConfirm2, signatureByteForConfirm2 := convertPointerToByte(originalMessageForConfirm2, signatureForConfirm2)
	originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, originalMessageByteForConfirm2)
	signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, signatureByteForConfirm2)

	for _, address := range p2 {
		rwMutex.Lock()
		originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

	go WrapperCrossPaymentConfirmRequest(rs.Pn, p, paymentInformation, originalMessageByteArrayForConfirm, signatureByteArrayForConfirm)

	go WrapperCrossPaymentConfirmRequest(rs.Pn, p2, _paymentInformation, originalMessageByteArrayForConfirm2, signatureByteArrayForConfirm2)

//	et := time.Since(StartTime)
//	fmt.Printf("et : %s \n", et)
	//fmt.Println("END!!")
	//return &pbXServer.CrossResult{Result: true}, nil

	for i:= 1; ; i++ {


		if <-Ch[int(rs.Pn)] == true {
			chConfirmed[rs.Pn]++
		}

		if chConfirmed[rs.Pn] == 6 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}

	//fmt.Println("END!!")
/*
	go func() {
		ChComplete[paymentNumToChId[rs.Pn]] <- true
	}()
*/
	return &pbXServer.CrossResult{Result: true}, nil
}

func (s *ServerGrpc) CrossPaymentPrepared(ctx context.Context, rs *pbXServer.CrossPaymentPrepareResMessage) (*pbXServer.CrossResult, error) {
	return &pbXServer.CrossResult{Result: true}, nil
}


func (s *ServerGrpc) CrossPaymentCommitted(ctx context.Context, rs *pbXServer.CrossPaymentCommitResMessage) (*pbXServer.CrossResult, error) {

	return &pbXServer.CrossResult{Result: true}, nil


/*
 *
 *
 * Refund
 *
	c1 := make(chan string, 1)
	var originalMessage *C.uchar
	var signature *C.uchar

	go func() {
		for C.ecall_cross_check_committed_unanimity_w(C.uint(pn), C.int(0)) != 1 {
		}
		timer[pn] = 1
		c1 <- "no time out"
	}()

	select {
	case res := <-c1:
		timer[pn] = 1
		fmt.Println(res)
	case <-time.After(time.Second * 18):
		timer[pn] = 2
	}

	if timer[pn] == 1 {	// no time out
		if committed[pn] == 1 {
			return &pbXServer.CrossResult{Result: true}, nil
		} else if committed[pn] == 0 {
			committed[pn] = 1
		}

		C.ecall_cross_create_all_confirm_req_msg_w(C.uint(pn), &originalMessage, &signature)
		originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

		r1, err := client1.CrossPaymentConfirmRequest(client1Context, &pbServer.CrossPaymentConfirmReqMessage{Pn: pn, From: "0xed26fa51b429c5c5922bee06184ec058c99a73c1", To: "0x59d853e0fef578589bd8609afbf1f5e5559a73ac", Amount: 1, OriginalMessage: originalMessageByte, Signature: signatureByte})

		if err != nil {
			log.Println(err)
			return &pbXServer.CrossResult{Result: false}, nil
		}

		log.Println(r1.GetResult())

		r2, err := client2.CrossPaymentConfirmRequest(client2Context, &pbServer.CrossPaymentConfirmReqMessage{Pn: pn, From: "0xed26fa51b429c5c5922bee06184ec058c99a73c1", To: "0x59d853e0fef578589bd8609afbf1f5e5559a73ac", Amount: 1, OriginalMessage: originalMessageByte, Signature: signatureByte})

		if err != nil {
			log.Println(err)
			return &pbXServer.CrossResult{Result: false}, nil
		}

		log.Println(r2.GetResult())

	} else if timer[pn] == 2 {	// time out
*/
		/*
		 *
		 *
		 * Refund message
		 */
/*
		 time.Sleep(time.Second * 25)

		 var refundMessage *C.uchar
		 var refundSignature *C.uchar

		 if committed[pn] == 0 {

			 committed[pn] = 1

			 C.ecall_cross_create_all_refund_req_msg_w(C.uint(pn), &refundMessage, &refundSignature)
			 refundMessageByte, refundSignatureByte := convertPointerToByte(refundMessage, refundSignature)

			 r1, err := client1.CrossPaymentRefundRequest(client1Context, &pbServer.CrossPaymentRefundReqMessage{Pn: pn, From: "0xed26fa51b429c5c5922bee06184ec058c99a73c1", To: "0x59d853e0fef578589bd8609afbf1f5e5559a73ac", Amount: 1, OriginalMessage: refundMessageByte, Signature: refundSignatureByte})	
			 if err != nil {
				 log.Println(err)
				 return &pbXServer.CrossResult{Result: true}, nil
			 }

			 log.Println(r1.GetResult())

			 r2, err := client2.CrossPaymentRefundRequest(client2Context, &pbServer.CrossPaymentRefundReqMessage{Pn: pn, From: "0xed26fa51b429c5c5922bee06184ec058c99a73c1", To: "0x59d853e0fef578589bd8609afbf1f5e5559a73ac", Amount: 1, OriginalMessage: refundMessageByte, Signature: refundSignatureByte})
		
			 if err != nil {
				 log.Println(err)
				 return &pbXServer.CrossResult{Result: true}, nil
			 }

			 log.Println(r2.GetResult())

			 fmt.Println("TIMER EXPIRED !!!!!")
			 return &pbXServer.CrossResult{Result: true}, nil
	
		 }
	}
*/
	elapsedTime := time.Since(StartTime)
	fmt.Println("****************************************************************")
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)

	log.Println("===== CROSS PAYMENT COMMIT END IN LV2 SERVER =====")
	return &pbXServer.CrossResult{Result: true}, nil
}

func crossPaymentRefund(pn int64) {

	log.Println("===== CROSS PAYMENT REFUND START =====")

	connectionForChain1, err := grpc.Dial(config.EthereumConfig["chain1ServerGrpcHost"] + ":" + config.EthereumConfig["chain1ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain1.Close()

	client1 := pbServer.NewServerClient(connectionForChain1)
	client1Context, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_refund_req_msg_w(C.uint(pn), &originalMessage, &signature)
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	r, err := client1.CrossPaymentRefundRequest(client1Context, &pbServer.CrossPaymentRefundReqMessage{Pn: pn, From: "0xed26fa51b429c5c5922bee06184ec058c99a73c1", To: "0x59d853e0fef578589bd8609afbf1f5e5559a73ac", Amount: 1, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(r.GetResult())

	log.Println("===== CROSS PAYMENT REFUND END =====")
}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	//log.Println("----- convertByteToPointer Server Start -----")
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

	return cOriginalMsg, cSignature
}

func convertMsgResByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	//log.Println("----- convertByteToPointer Server Start -----")
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

	return cOriginalMsg, cSignature
}

func convertPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(216),
		Cap:  int(216),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

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

	defer C.free(unsafe.Pointer(originalMsg))
	defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}

func ChanCreate() {

	if chanCreateCheck == 0 {
		for i:= range Ch {
			Ch[i] = make(chan bool)
			ChComplete[i] = make(chan bool)
		}

		for i:= range prepareMsgCreation {
			prepareMsgCreation[i] = make(chan bool)
		}

		for i:= range commitMsgCreation {
			commitMsgCreation[i] = make(chan bool)
		}

		for i:= range confirmMsgCreation {
			confirmMsgCreation[i] = make(chan bool)
		}

	} else {
		return
	}

	chanCreateCheck = 1
	fmt.Println("Channel Create !")
}

func WrapperCrossPaymentPrepareRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByte []byte, signatureByte []byte) (bool) {

	/*
	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()
	*/

	var AG = AG{}
	AG.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		AG.pn = pn
		AG.address = address
		AG.originalMessageByte = originalMessageByte
		AG.signatureByte = signatureByte

		wg.Add(1)
		sendCrossPaymentPrepareRequestPool.Invoke(AG)
	}
	return true
}

func WrapperCrossPaymentCommitRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArray [][]byte, signatureByteArray [][]byte) (bool) {

	var UD = UD{}
	UD.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = pn
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArray
		UD.signatureByteArray = signatureByteArray

		wg.Add(1)
		go sendCrossPaymentCommitRequestPool.Invoke(UD)
	}


	return true
//	Ch[int(paymentNum)] <- true
}

func WrapperCrossPaymentConfirmRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation, originalMessageByteArrayForConfirm [][]byte, signatureByteArrayForConfirm [][]byte) (bool) {

	var UD = UD{}
	UD.paymentInformation = make(map[string]PaymentInformation)
	for _, address := range p {
		UD.pn = pn
		UD.address = address
		UD.originalMessageByteArray = originalMessageByteArrayForConfirm
		UD.signatureByteArray = signatureByteArrayForConfirm

		wg.Add(1)
		go sendCrossPaymentConfirmRequestPool.Invoke(UD)
	}
	return true
}

func GrpcConnection() {

	var err error
/*	tempConn := make(map[string]*grpc.ClientConn)

	tempConn["141.223.121.165:50004"], err = grpc.Dial("141.223.121.165:50004", grpc.WithInsecure())
	if err != nil {
		log.Fatal("Conn err !")
		return
	}

	tempConn["141.223.121.166:50004"], err = grpc.Dial("141.223.121.166:50004", grpc.WithInsecure())
	if err != nil {
		log.Fatal("Conn err !")
		return
	}

	tempConn["141.223.121.169:50004"], err = grpc.Dial("141.223.121.169:50004", grpc.WithInsecure())
	if err != nil {
		log.Fatal("Conn err !")
		return
	}

	connectionForServer = tempConn
*/
//	str := []string{"141.223.121.167:50001", "141.223.121.167:50001", "141.223.121.167:50001"}

//	tempClient := make(map[string]map[int]*grpc.ClientConn)

	var tempConnC1 [1000]*grpc.ClientConn// make(map[int]*grpc.ClientConn)
	var tempConnC2 [1000]*grpc.ClientConn
	var tempConnC3 [1000]*grpc.ClientConn
	var tempConnC4 [1000]*grpc.ClientConn
	var tempConnC5 [1000]*grpc.ClientConn
	var tempConnC6 [1000]*grpc.ClientConn

	for i:=0; i<10; i++ {

//		tempConn := []*grpc.ClientConn// make(map[int]*grpc.ClientConn)
//		tempClient1[i] = tempConn

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

/*
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

	tempConn["141.223.121.165:50001"], err = grpc.Dial("141.223.121.165:50001", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.166:50002"], err = grpc.Dial("141.223.121.166:50002", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.169:50003"], err = grpc.Dial("141.223.121.169:50003", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	connectionForClient = tempConn
*/

	for i:=0; i<100; i++ {
		Cross_Client[i] = pbXServer.NewCross_ServerClient(Cross_connection)
		Cross_ClientContext[i], _ = context.WithTimeout(context.Background(), time.Second*180)

		Client[i] = pbServer.NewServerClient(connection)
		ClientContext[i], _ = context.WithTimeout(context.Background(), time.Second*180)

	}

	fmt.Println("Grpc Connection !!")
}

func GetClientInfo() {

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

}

