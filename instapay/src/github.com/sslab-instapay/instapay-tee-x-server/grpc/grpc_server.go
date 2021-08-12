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

var clientIP1 = "141.223.121.167:50001"
var clientIP2 = "141.223.121.168:50002"
var clientIP3 = "141.223.121.251:50003"

var clientIP4 = "141.223.121.165:50001"
var clientIP5 = "141.223.121.166:50002"
var clientIP6 = "141.223.121.169:50003"

var clientAddr1ForChain1 = "f55ba9376db959fab2af86d565325829b08ea3c4"
var clientAddr2ForChain1 = "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"
var clientAddr3ForChain1 = "70603f1189790fcd0fd753a7fef464bdc2c2ad36"

var clientAddr1ForChain2 = "f4444529d6221122d1712c52623ba119a60609e3"
var clientAddr2ForChain2 = "d95da40bbd2001abf1a558c0b1dffd75940b8fd9"
var clientAddr3ForChain2 = "73d8e5475278f7593b5293beaa45fb53f34c9ad2"

const (
	NumOfParticipants = 5
	EnclaveFailure = 9999
	PaymentFailure = 999999
)

var checkChFirstOrNot [10000]int
var chIdToPaymentNum [10000]int

var prepareMsgCreation [500000]chan bool
var prepareMsgCreationSuccess [100000]int
var commitMsgCreation [500000]chan bool
var commitMsgCreationSuccess [100000]int
var confirmMsgCreation [500000]chan bool
var confirmMsgCreationSuccess [100000]int

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
	pbXServer.UnimplementedCross_ServerServer
}

var connClient = make(map[string][1000]*grpc.ClientConn) //map[int]*grpc.ClientConn)

var Cross_connection, err = grpc.Dial(config.EthereumConfig["crossServerGrpcHost"]+":"+config.EthereumConfig["crossServerGrpcPort"], grpc.WithInsecure())
var Cross_Client [1000]pbXServer.Cross_ServerClient
var Cross_ClientContext [1000]context.Context

var connection, _ = grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
var Client [1000]pbServer.ServerClient //= pbServer.NewServerClient(connection)
var ClientContext [1000]context.Context

var connectionForServer = make(map[string]*grpc.ClientConn)

var channelForRecevingMsg [500000]chan bool
var emptyChannel [500000]chan bool
var preparedStatus [100000]int
var committedStatus [100000]int
var confirmedStatus [100000]int

var chanCreateCheck = 0

var rwMutex = new(sync.RWMutex)
var StartTime time.Time

var channelId = 1

type PaymentInformation struct {
	ChannelInform []C.uint
	AmountInform  []C.int
}

var paymentInformationForChain1 = make(map[string]PaymentInformation)
var participantsForChain1 []string

var paymentInformationForChain2 = make(map[string]PaymentInformation)
var participantsForChain2 []string

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

		addr := []C.uchar(address)

		for ; ; {
			result := C.ecall_cross_verify_all_prepared_res_msg_w(agreementOriginalMessage, signature, &addr[0])

			if result == EnclaveFailure {
				break
			}
		}

		var clientPrepareMsgRes = AG{}
		clientPrepareMsgRes.originalMessageByte = r.OriginalMessage
		clientPrepareMsgRes.signatureByte = r.Signature

		rwMutex.Lock()
		paymentPrepareMsgRes[strconv.FormatInt(pn, 10)+address] = clientPrepareMsgRes
		rwMutex.Unlock()
		channelForRecevingMsg[pn] <- true
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
r, err := client.CrossPaymentCommitClientRequest(context.Background(), &pbClient.CrossPaymentCommitReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray, NumOfParticipants: NumOfParticipants })//int64(len(originalMessageByteArray))})


	if err != nil {
		log.Println("client Commit Request err : ", err, clientAddr[address])
	}


	if r.Result {

		updateOriginalMessage, signature := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)
		//C.ecall_cross_verify_all_committed_res_msg_temp_w(updateOriginalMessage, signature)

		addr := []C.uchar(address)

		for ; ; {
			result := C.ecall_cross_verify_all_committed_res_msg_w(updateOriginalMessage, signature, &addr[0])

			if result == EnclaveFailure {
				break
			}
		}

		var clientCommitMsgRes = AG{}
		clientCommitMsgRes.originalMessageByte = r.OriginalMessage
		clientCommitMsgRes.signatureByte = r.Signature

		rwMutex.Lock()
		paymentCommitMsgRes[strconv.FormatInt(pn, 10)+address] = clientCommitMsgRes
		rwMutex.Unlock()
		channelForRecevingMsg[pn] <- true

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

	_, err := client.CrossPaymentConfirmClientRequest(context.Background(), &pbClient.CrossPaymentConfirmReqClientMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray, NumOfParticipants: NumOfParticipants}) //int64(len(originalMessageByteArray))})

	if err != nil {
		log.Println("client Confirm Request err : ", err)
	}

	channelForRecevingMsg[pn] <- true
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
	var channelInform1, channelInform2, channelInform3, channelInform4, channelInform5, channelInform6 []C.uint
	var _channelInform1, _channelInform2, _channelInform3 []C.uint

	var amountInform1, amountInform2, amountInform3, amountInform4, amountInform5, amountInform6 []C.int

	channelInform1 = append(channelInform1, C.uint(firstTempChId))
	channelInform2 = append(channelInform2, C.uint(firstTempChId))
	channelInform2 = append(channelInform2, C.uint(secondTempChId))
	channelInform3 = append(channelInform3, C.uint(secondTempChId))

	// 4 parties
	channelInform3 = append(channelInform3, C.uint(firstTempChId))
	channelInform4 = append(channelInform4, C.uint(firstTempChId))
	// 5 parties
	channelInform4 = append(channelInform4, C.uint(secondTempChId))
	channelInform5 = append(channelInform5, C.uint(secondTempChId))
	// 6 parties
	channelInform5 = append(channelInform5, C.uint(firstTempChId))
	channelInform6 = append(channelInform6, C.uint(firstTempChId))

	amountInform1 = append(amountInform1, C.int(-amount))
	amountInform2 = append(amountInform2, C.int(amount))
	amountInform2 = append(amountInform2, C.int(-amount))
	amountInform3 = append(amountInform3, C.int(amount))

	// 4 parties
	amountInform3 = append(amountInform3, C.int(-amount))
	amountInform4 = append(amountInform4, C.int(amount))
	// 5 parties
	amountInform4 = append(amountInform4, C.int(-amount))
	amountInform5 = append(amountInform5, C.int(amount))
	// 6 parties
	amountInform5 = append(amountInform5, C.int(-amount))
	amountInform6 = append(amountInform6, C.int(amount))

	_channelInform1 = append(_channelInform1, C.uint(firstTempChId))
	_channelInform2 = append(_channelInform2, C.uint(firstTempChId))
	//      channelId++
	_channelInform2 = append(_channelInform2, C.uint(secondTempChId))
	_channelInform3 = append(_channelInform3, C.uint(secondTempChId))

	paymentInform1 := PaymentInformation{ChannelInform: channelInform1, AmountInform: amountInform1}
	paymentInform2 := PaymentInformation{ChannelInform: channelInform2, AmountInform: amountInform2}
	paymentInform3 := PaymentInformation{ChannelInform: channelInform3, AmountInform: amountInform3}

	// 4 parties
	paymentInform4 := PaymentInformation{ChannelInform: channelInform4, AmountInform: amountInform4}
	// 5 parties
	paymentInform5 := PaymentInformation{ChannelInform: channelInform5, AmountInform: amountInform5}
	// 6 parties
	paymentInform6 := PaymentInformation{ChannelInform: channelInform6, AmountInform: amountInform6}

	_paymentInform1 := PaymentInformation{ChannelInform: _channelInform1, AmountInform: amountInform1}
	_paymentInform2 := PaymentInformation{ChannelInform: _channelInform2, AmountInform: amountInform2}
	_paymentInform3 := PaymentInformation{ChannelInform: _channelInform3, AmountInform: amountInform3}

         //paymentInformation := make(map[string]PaymentInformation)
	 rwMutex.Lock()
	 paymentInformationForChain1["f55ba9376db959fab2af86d565325829b08ea3c4"] = paymentInform1
	 paymentInformationForChain1["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = paymentInform2
	 paymentInformationForChain1["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = paymentInform3
	 // 4 parties
	 paymentInformationForChain1["f4444529d6221122d1712c52623ba119a60609e3"] = paymentInform4
	 // 5 parties
	 paymentInformationForChain1["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = paymentInform5
	 // 6 parties
	 paymentInformationForChain1["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = paymentInform6

	 paymentInformationForChain2["f4444529d6221122d1712c52623ba119a60609e3"] = _paymentInform1
	 paymentInformationForChain2["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = _paymentInform2
	 paymentInformationForChain2["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = _paymentInform3
	 rwMutex.Unlock()

//         log.Println("===== SearchPath End =====")
	 return participantsForChain1, participantsForChain2, paymentInformationForChain1, paymentInformationForChain2
}

func (s *ServerGrpc) CrossPaymentRequest(ctx context.Context, rs *pbXServer.CrossPaymentMessage) (*pbXServer.CrossResult, error) {

//	StartTime = time.Now()

	var originalMessageForPrepare *C.uchar
        var signatureForPrepare *C.uchar
//	var originalMessageForPrepare2 *C.uchar
//        var signatureForPrepare2 *C.uchar

	var originalMessageForCommit *C.uchar
        var signatureForCommit *C.uchar
//	var originalMessageForCommit2 *C.uchar
//        var signatureForCommit2 *C.uchar

	var originalMessageForConfirm *C.uchar
        var signatureForConfirm *C.uchar
//	var originalMessageForConfirm2 *C.uchar
//        var signatureForConfirm2 *C.uchar

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

//	var originalMessageByteArray2 [][]byte
//	var signatureByteArray2 [][]byte

	var originalMessageByteArrayForConfirm [][]byte
	var signatureByteArrayForConfirm [][]byte

//	var originalMessageByteArrayForConfirm2 [][]byte
//	var signatureByteArrayForConfirm2 [][]byte

	rwMutex.Lock()
	firstTempChId := channelId
	secondTempChId := channelId+1

	channelId+=2
	if channelId > 1000 {
		channelId = 1
	}

	rwMutex.Unlock()

//	go func() {
		if chIdToPaymentNum[firstTempChId] == 0 {
		// if channel ID is used first,
		chIdToPaymentNum[firstTempChId] = 1

		} else if chIdToPaymentNum[firstTempChId] == 1 {
			data := <-emptyChannel[chIdToPaymentNum[firstTempChId]]
			if data == true { } // else, wait
		}
//	}()

//	fmt.Println(firstTempChId)
	participantsForChain1, participantsForChain2, paymentInformationForChain1, paymentInformationForChain2 = SearchPath(int64(rs.Pn), rs.ChainVal[0], firstTempChId, secondTempChId)

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
			C.uint(rs.ChainVal[0]),
			&chain2Sender[0],
			&chain2MiddleMan[0],
			&chain2Receiver[0],
			C.uint(rs.ChainVal[1]),
			nil,
			nil,
			nil,
			C.uint(0),
			C.uint(NumOfParticipants))

			if PaymentNum != PaymentFailure {
				break
			}
	}

	sender := []C.uchar(participantsForChain1[0])
	middleMan := []C.uchar(participantsForChain1[1])
	receiver := []C.uchar(participantsForChain1[2])
	receiver2 := []C.uchar(participantsForChain1[3])
	receiver3 := []C.uchar(participantsForChain1[4])
/*
	_sender2 := []C.uchar(participantsForChain2[0])
	_middleMan2 := []C.uchar(participantsForChain2[1])
	_receiver2 := []C.uchar(participantsForChain2[2])
*/
	rwMutex.Lock()
	paymentInformation1 := paymentInformationForChain1[participantsForChain1[0]]
	paymentInformation2 := paymentInformationForChain1[participantsForChain1[1]]
	paymentInformation3 := paymentInformationForChain1[participantsForChain1[2]]
	paymentInformation4 := paymentInformationForChain1[participantsForChain1[3]]
	paymentInformation5 := paymentInformationForChain1[participantsForChain1[4]]
/*
	_paymentInformation1 := paymentInformationForChain2[participantsForChain2[0]]
	_paymentInformation2 := paymentInformationForChain2[participantsForChain2[1]]
	_paymentInformation3 := paymentInformationForChain2[participantsForChain2[2]]
*/
	rwMutex.Unlock()

	// for chain1
	channelSlice1 := paymentInformation1.ChannelInform
	amountSlice1 := paymentInformation1.AmountInform

	channelSlice2 := paymentInformation2.ChannelInform
	amountSlice2:= paymentInformation2.AmountInform

	channelSlice3 := paymentInformation3.ChannelInform
	amountSlice3 := paymentInformation3.AmountInform

	channelSlice4 := paymentInformation4.ChannelInform
//	amountSlice4 := paymentInformation4.AmountInform

	channelSlice5 := paymentInformation5.ChannelInform
//	amountSlice5 := paymentInformation5.AmountInform


	// for chain2
/*	_channelSlice1 := _paymentInformation1.ChannelInform
	_amountSlice1 := _paymentInformation1.AmountInform

	_channelSlice2 := _paymentInformation2.ChannelInform
	_amountSlice2:= _paymentInformation2.AmountInform

	_channelSlice3 := _paymentInformation3.ChannelInform
	_amountSlice3 := _paymentInformation3.AmountInform
*/

//	st := time.Now()

//	if rs.Pn%2 == 1 {
		go func(){
			for ; ; {
				result := C.ecall_cross_create_all_prepare_req_msg_w2(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], &receiver2[0], &receiver3[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], C.uint(len(channelSlice4)), &channelSlice4[0], C.uint(len(channelSlice5)), &channelSlice5[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForPrepare, &signatureForPrepare)

				if result == EnclaveFailure {
					prepareMsgCreation[rs.Pn] <- true
					break
				} else {
					C.free(unsafe.Pointer(originalMessageForPrepare))
					C.free(unsafe.Pointer(signatureForPrepare))
				}
			}
		}()
/*	} else {

	fmt.Println(">> ",  originalMessageForPrepare)
	return &pbXServer.CrossResult{Result: true}, nil


		go func() {

			for ; ; {
				result := C.ecall_cross_create_all_prepare_req_msg_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(_channelSlice1)), &_channelSlice1[0], C.uint(len(_channelSlice2)), &_channelSlice2[0], C.uint(len(_channelSlice3)), &_channelSlice3[0], &_amountSlice1[0], &_amountSlice2[0], &_amountSlice3[0], &originalMessageForPrepare2, &signatureForPrepare2)
				if result == EnclaveFailure {
					prepareMsgCreation[rs.Pn] <- true
					break
				} else {
					C.free(unsafe.Pointer(originalMessageForPrepare2))
					C.free(unsafe.Pointer(signatureForPrepare2))
				}
			}
		}()
//	}
*/
	for i:=1; ; i++ {
		if <-prepareMsgCreation[rs.Pn] == true {
			prepareMsgCreationSuccess[rs.Pn]++
		}

		if prepareMsgCreationSuccess[rs.Pn] == 1 {
			break
		}
	}

//	if rs.Pn%2 == 1 {
		originalMessageByteForPrepare, signatureByteForPrepare := convertPointerToByte(originalMessageForPrepare, signatureForPrepare)
		go WrapperCrossPaymentPrepareRequest(rs.Pn, participantsForChain1, paymentInformationForChain1, originalMessageByteForPrepare, signatureByteForPrepare)
/*	} else {
		originalMessageByteForPrepare2, signatureByteForPrepare2 := convertPointerToByte(originalMessageForPrepare2, signatureForPrepare2)
		go WrapperCrossPaymentPrepareRequest(rs.Pn, participantsForChain2, paymentInformationForChain2, originalMessageByteForPrepare2, signatureByteForPrepare2)
//	}
*/
	for i:= 1; ; i++ {

		if <-channelForRecevingMsg[int(rs.Pn)] == true {
			preparedStatus[rs.Pn]++
		}

		if preparedStatus[rs.Pn] == NumOfParticipants {
			break
		} else { }
	}

//	fmt.Println("END")
//	return &pbXServer.CrossResult{Result: true}, nil

//	if rs.Pn%2 == 1 {

		go func() {
			for ; ; {
				result := C.ecall_cross_create_all_commit_req_msg_w2(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], &receiver2[0], &receiver3[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], C.uint(len(channelSlice4)), &channelSlice4[0], C.uint(len(channelSlice5)), &channelSlice5[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForCommit, &signatureForCommit)

				if result == EnclaveFailure {
					commitMsgCreation[rs.Pn] <- true
					break
				} else {
					C.free(unsafe.Pointer(originalMessageForCommit))
					C.free(unsafe.Pointer(signatureForCommit))
				}
			}
		}()
/*	} else {
		go func() {
			for ; ; {
				result := C.ecall_cross_create_all_commit_req_msg_w(C.uint(rs.Pn), &_sender2[0], &_middleMan2[0], &_receiver2[0], C.uint(len(_channelSlice1)), &_channelSlice1[0], C.uint(len(_channelSlice2)), &_channelSlice2[0], C.uint(len(_channelSlice3)), &_channelSlice3[0], &_amountSlice1[0], &_amountSlice2[0], &_amountSlice3[0], &originalMessageForCommit2, &signatureForCommit2)
				if result == EnclaveFailure {
					commitMsgCreation[rs.Pn] <- true
					break
				} else {
					C.free(unsafe.Pointer(originalMessageForCommit2))
					C.free(unsafe.Pointer(signatureForCommit2))
				}
			}
		}()
//	}
*/
	for i:=1; ; i++ {
		if <-commitMsgCreation[rs.Pn] == true {
			commitMsgCreationSuccess[rs.Pn]++
		}

		if commitMsgCreationSuccess[rs.Pn] == 1 {
			break
		}
	}

//	if rs.Pn%2 == 1 {

		originalMessageByteForCommit, signatureByteForCommit := convertPointerToByte(originalMessageForCommit, signatureForCommit)

		originalMessageByteArray = append(originalMessageByteArray, originalMessageByteForCommit)
		signatureByteArray = append(signatureByteArray, signatureByteForCommit)

		for _, address := range participantsForChain1 {
			rwMutex.Lock()
			originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
			signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
			rwMutex.Unlock()
		}
/*	} else {

		originalMessageByteForCommit2, signatureByteForCommit2 := convertPointerToByte(originalMessageForCommit2, signatureForCommit2)

		originalMessageByteArray2 = append(originalMessageByteArray2, originalMessageByteForCommit2)
		signatureByteArray2 = append(signatureByteArray2, signatureByteForCommit2)

		for _, address := range participantsForChain2 {
			rwMutex.Lock()
			originalMessageByteArray2 = append(originalMessageByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
			signatureByteArray2 = append(signatureByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
			rwMutex.Unlock()
		}
//	}
*/
//	if rs.Pn%2 == 1 {
		go WrapperCrossPaymentCommitRequest(rs.Pn, participantsForChain1, paymentInformationForChain1, originalMessageByteArray, signatureByteArray)
/*	} else {
		go WrapperCrossPaymentCommitRequest(rs.Pn, participantsForChain2, paymentInformationForChain2, originalMessageByteArray2, signatureByteArray2)
//	}
*/
	for i:= 1; ; i++ {

		if <-channelForRecevingMsg[int(rs.Pn)] == true {
			committedStatus[rs.Pn]++
		}

		if committedStatus[rs.Pn] == NumOfParticipants {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}


//	fmt.Println("END!")
//	return &pbXServer.CrossResult{Result: true}, nil

//	if rs.Pn%2 == 1 {

		go func() {
			for ; ; {
				result := C.ecall_cross_create_all_confirm_req_msg_w2(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], &receiver2[0], &receiver3[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], C.uint(len(channelSlice4)), &channelSlice4[0], C.uint(len(channelSlice5)), &channelSlice5[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessageForConfirm, &signatureForConfirm)

				if result == EnclaveFailure {
					confirmMsgCreation[rs.Pn] <- true
					break
				} else {

					C.free(unsafe.Pointer(originalMessageForConfirm))
					C.free(unsafe.Pointer(signatureForConfirm))
				}
			}
		}()
/*	} else {
		go func() {
			for ; ; {
				result := C.ecall_cross_create_all_confirm_req_msg_w(C.uint(rs.Pn), &_sender2[0], &_middleMan2[0], &_receiver2[0], C.uint(len(_channelSlice1)), &_channelSlice1[0], C.uint(len(_channelSlice2)), &_channelSlice2[0], C.uint(len(_channelSlice3)), &_channelSlice3[0], &_amountSlice1[0], &_amountSlice2[0], &_amountSlice3[0], &originalMessageForConfirm2, &signatureForConfirm2)
				if result == EnclaveFailure {
					confirmMsgCreation[rs.Pn] <- true
					break
				} else {
					C.free(unsafe.Pointer(originalMessageForConfirm2))
					C.free(unsafe.Pointer(signatureForConfirm2))
				}
			}
		}()
//	}
*/
	for i:=1; ; i++ {
		if <-confirmMsgCreation[rs.Pn] == true {
			confirmMsgCreationSuccess[rs.Pn]++
		}

		if confirmMsgCreationSuccess[rs.Pn] == 1 {
			break
		}
	}

//	if rs.Pn%2 == 1 {

		originalMessageByteForConfirm, signatureByteForConfirm := convertPointerToByte(originalMessageForConfirm, signatureForConfirm)
		originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, originalMessageByteForConfirm)
		signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, signatureByteForConfirm)

		for _, address := range participantsForChain1 {
			rwMutex.Lock()
			originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
			signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
			rwMutex.Unlock()
		}
/*	} else {


		originalMessageByteForConfirm2, signatureByteForConfirm2 := convertPointerToByte(originalMessageForConfirm2, signatureForConfirm2)
		originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, originalMessageByteForConfirm2)
		signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, signatureByteForConfirm2)

		for _, address := range participantsForChain2 {
			rwMutex.Lock()
			originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
			signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
			rwMutex.Unlock()
		}
//	}
*/

//	if rs.Pn%2 == 1 {
		go WrapperCrossPaymentConfirmRequest(rs.Pn, participantsForChain1, paymentInformationForChain1, originalMessageByteArrayForConfirm, signatureByteArrayForConfirm)
/*	} else {
		go WrapperCrossPaymentConfirmRequest(rs.Pn, participantsForChain2, paymentInformationForChain2, originalMessageByteArrayForConfirm2, signatureByteArrayForConfirm2)
//	}
*/
	for i:= 1; ; i++ {


		if <-channelForRecevingMsg[int(rs.Pn)] == true {
			confirmedStatus[rs.Pn]++
		}

		if confirmedStatus[rs.Pn] == NumOfParticipants {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}

	//fmt.Println("END!!")

	go func() {
		emptyChannel[chIdToPaymentNum[firstTempChId]] <- true
	}()

//	elapsedTime := time.Since(StartTime)
//	fmt.Printf("execution time : %s", elapsedTime)

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
		Len:  int(328),
		Cap:  int(328),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 328; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

//	defer C.free(unsafe.Pointer(originalMsg))
	defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}

func ChanCreate() {

	if chanCreateCheck == 0 {
		for i:= range channelForRecevingMsg {
			channelForRecevingMsg[i] = make(chan bool)
			emptyChannel[i] = make(chan bool)
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

		tempConnC1[i], err = grpc.Dial(clientIP1, grpc.WithInsecure())
		if err != nil {
			log.Fatal("conn err ", err)
		}

		tempConnC2[i], err = grpc.Dial(clientIP2, grpc.WithInsecure())
		tempConnC3[i], err = grpc.Dial(clientIP3, grpc.WithInsecure())
		tempConnC4[i], err = grpc.Dial(clientIP4, grpc.WithInsecure())
		tempConnC5[i], err = grpc.Dial(clientIP5, grpc.WithInsecure())
		tempConnC6[i], err = grpc.Dial(clientIP6, grpc.WithInsecure())
	}

	connClient[clientIP1] = tempConnC1
	connClient[clientIP2] = tempConnC2
	connClient[clientIP3] = tempConnC3
	connClient[clientIP4] = tempConnC4
	connClient[clientIP5] = tempConnC5
	connClient[clientIP6] = tempConnC6

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

	for i:=0; i<1000; i++ {
		Cross_Client[i] = pbXServer.NewCross_ServerClient(Cross_connection)
		Cross_ClientContext[i], _ = context.WithTimeout(context.Background(), time.Second*180)

		Client[i] = pbServer.NewServerClient(connection)
		ClientContext[i], _ = context.WithTimeout(context.Background(), time.Second*180)

	}

	fmt.Println("Grpc Connection !!")
}

func GetClientInfo() {
/*
	participantsForChain1 = append(participantsForChain1, "f55ba9376db959fab2af86d565325829b08ea3c4")
	participantsForChain1 = append(participantsForChain1, "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")
	participantsForChain1 = append(participantsForChain1, "70603f1189790fcd0fd753a7fef464bdc2c2ad36")

	participantsForChain2 = append(participantsForChain2, "f4444529d6221122d1712c52623ba119a60609e3")
	participantsForChain2 = append(participantsForChain2, "d95da40bbd2001abf1a558c0b1dffd75940b8fd9")
	participantsForChain2 = append(participantsForChain2, "73d8e5475278f7593b5293beaa45fb53f34c9ad2")

	clientAddr["f55ba9376db959fab2af86d565325829b08ea3c4"] = "141.223.121.167:50001"
	clientAddr["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = "141.223.121.168:50002"
	clientAddr["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = "141.223.121.251:50003"

	clientAddr["f4444529d6221122d1712c52623ba119a60609e3"] = "141.223.121.165:50001"
	clientAddr["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = "141.223.121.166:50002"
	clientAddr["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = "141.223.121.169:50003"
*/
	participantsForChain1 = append(participantsForChain1, clientAddr1ForChain1)
	participantsForChain1 = append(participantsForChain1, clientAddr2ForChain1)
	participantsForChain1 = append(participantsForChain1, clientAddr3ForChain1)
	participantsForChain1 = append(participantsForChain1, clientAddr1ForChain2)	// 4 parties
	participantsForChain1 = append(participantsForChain1, clientAddr2ForChain2)	// 5 parties

	participantsForChain2 = append(participantsForChain2, clientAddr1ForChain2)
	participantsForChain2 = append(participantsForChain2, clientAddr2ForChain2)
	participantsForChain2 = append(participantsForChain2, clientAddr3ForChain2)

	clientAddr[clientAddr1ForChain1] = clientIP1
	clientAddr[clientAddr2ForChain1] = clientIP2
	clientAddr[clientAddr3ForChain1] = clientIP3

	clientAddr[clientAddr1ForChain2] = clientIP4
	clientAddr[clientAddr2ForChain2] = clientIP5
	clientAddr[clientAddr3ForChain2] = clientIP6
}
