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
)

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
	pbXServer.UnimplementedCross_ServerServer
}

var connectionForServer = make(map[string]*grpc.ClientConn)

var Ch [100000]chan bool
var ChComplete [100000]chan bool
//var Ch chan bool = make(chan bool)
//var Ch = make(map[int](chan bool), 3)
var chprepared [100000]int
var chCommitted [100000]int
var chanCreateCheck = 0

var prepared [100000]int
var committed [100000]int
var timer [100000]int

var rwMutex = new(sync.RWMutex)
var StartTime time.Time

var ChainFrom []string
var ChainTo   []string
var ChainVal  []int64

var StartTime1 time.Time
var StartTime2 time.Time
var StartTime3 time.Time

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

var sendCrossPaymentPrepareRequestPool, _ = ants.NewPoolWithFunc(10000, func(i interface{}) {
	SendCrossPaymentPrepareRequest(i)
	wg.Done()
})

var sendCrossPaymentCommitRequestPool, _ = ants.NewPoolWithFunc(10000, func(i interface{}) {
	SendCrossPaymentCommitRequest(i)
	wg.Done()
})

var sendCrossPaymentConfirmRequestPool, _ = ants.NewPoolWithFunc(10000, func(i interface{}) {
	SendCrossPaymentConfirmRequest(i)
	wg.Done()
})

func SendCrossPaymentPrepareRequest(i interface{}) {

	pn := i.(AG).pn
	address := i.(AG).address
	originalMessageByte := i.(AG).originalMessageByte
	signatureByte := i.(AG).signatureByte

	client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])

	if client == nil {
		log.Fatal("client conn err")
	}

	r, err := client.AgreementRequest(context.Background(), &pbClient.AgreeRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})

	if err != nil {
		log.Println("client AgreementRequest err : ", err)
	}

	if r.Result {
		agreementOriginalMessage, signature := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)

		C.ecall_cross_verify_all_prepared_res_msg_temp_w(agreementOriginalMessage, signature)
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

	client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])

	if client == nil {
		log.Fatal("client conn err")
	}


	r, err := client.UpdateRequest(context.Background(), &pbClient.UpdateRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray})

	if err != nil {
		log.Println("client Commit Request err : ", err)
	}

	if r.Result {
		updateOriginalMessage, signature := convertMsgResByteToPointer(r.OriginalMessage, r.Signature)
		C.ecall_cross_verify_all_committed_res_msg_temp_w(updateOriginalMessage, signature)

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

	client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])

	if client == nil {
		log.Fatal("client conn err")
	}

	_, err := client.ConfirmPayment(context.Background(), &pbClient.ConfirmRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByteArray, Signature: signatureByteArray})

	if err != nil {
		log.Println("client Confirm Request err : ", err)
	}

		//secp256k1.VerifySignature([]byte(address), r.OriginalMessage, r.Signature)
	return
}

func StartGrpcServer() {

	ChanCreate()
	GrpcConnection()
	GetClientInfo()

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

	 paymentInformation["f55ba9376db959fab2af86d565325829b08ea3c4"] = paymentInform1
	 paymentInformation["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = paymentInform2
	 paymentInformation["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = paymentInform3

	 _paymentInformation["f4444529d6221122d1712c52623ba119a60609e3"] = paymentInform1
	 _paymentInformation["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = paymentInform2
	 _paymentInformation["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = paymentInform3

//         log.Println("===== SearchPath End =====")
	 return p, p2, paymentInformation, _paymentInformation
}

func (s *ServerGrpc) CrossPaymentRequest(ctx context.Context, rs *pbXServer.CrossPaymentMessage) (*pbXServer.CrossResult, error) {


	var originalMessage *C.uchar
        var signature *C.uchar
	var originalMessage2 *C.uchar
        var signature2 *C.uchar

//	p, p2, paymentInformation, _paymentInformation = SearchPath(int64(rs.Pn), 1, 1, 2)

	sender := []C.uchar(p[0])
	middleMan := []C.uchar(p[1])
	receiver := []C.uchar(p[2])

	sender2 := []C.uchar(p2[0])
	middleMan2 := []C.uchar(p2[1])
	receiver2 := []C.uchar(p2[2])

	paymentInformation1 := paymentInformation[p[0]]
	paymentInformation2 := paymentInformation[p[1]]
	paymentInformation3 := paymentInformation[p[2]]
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


        //C.ecall_cross_create_all_prepare_req_msg_w(C.uint(rs.Pn), &originalMessage, &signature)
	C.ecall_cross_create_all_prepare_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage, &signature)

	C.ecall_cross_create_all_prepare_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage2, &signature2)

        originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
        originalMessageByte2, signatureByte2 := convertPointerToByte(originalMessage2, signature2)


//	for i := 1; i<=1; i++ {
		go WrapperCrossPaymentPrepareRequest(rs.Pn, p, paymentInformation, originalMessageByte, signatureByte)

		go WrapperCrossPaymentPrepareRequest(rs.Pn, p2, _paymentInformation, originalMessageByte2, signatureByte2)

//	}

	for i:= 1; i<=6; i++ {

		var data = <-Ch[int(rs.Pn)]

		if data == true {
			chprepared[rs.Pn]++
		}

		if chprepared[rs.Pn] == 6 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}

	}

	C.ecall_cross_create_all_commit_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage, &signature)

	C.ecall_cross_create_all_commit_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage2, &signature2)

	var originalMessageByteArray [][]byte
	var signatureByteArray [][]byte

	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)
	originalMessageByteArray = append(originalMessageByteArray, originalMessageByte)
	signatureByteArray = append(signatureByteArray, signatureByte)

	for _, address := range p {
		rwMutex.Lock()
		originalMessageByteArray = append(originalMessageByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArray = append(signatureByteArray, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

	var originalMessageByteArray2 [][]byte
	var signatureByteArray2 [][]byte

	originalMessageByte2, signatureByte2 = convertPointerToByte(originalMessage2, signature2)
	originalMessageByteArray2 = append(originalMessageByteArray2, originalMessageByte2)
	signatureByteArray2 = append(signatureByteArray2, signatureByte2)

	for _, address := range p2 {
		rwMutex.Lock()
		originalMessageByteArray2 = append(originalMessageByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArray2 = append(signatureByteArray2, paymentPrepareMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}


	for i := 1; i<=1; i++ {
		go WrapperCrossPaymentCommitRequest(rs.Pn, p, paymentInformation, originalMessageByteArray, signatureByteArray)

		go WrapperCrossPaymentCommitRequest(rs.Pn, p2, _paymentInformation, originalMessageByteArray2, signatureByteArray2)
	}

	for i:= 1; i<=6; i++ {

		var data = <-Ch[int(rs.Pn)]

		if data == true {
			chCommitted[rs.Pn]++
		}

		if chCommitted[rs.Pn] == 6 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}
//	return &pbXServer.CrossResult{Result: true}, nil

	C.ecall_cross_create_all_confirm_req_msg_temp_w(C.uint(rs.Pn), &sender[0], &middleMan[0], &receiver[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage, &signature)

	C.ecall_cross_create_all_confirm_req_msg_temp_w(C.uint(rs.Pn), &sender2[0], &middleMan2[0], &receiver2[0], C.uint(len(channelSlice1)), &channelSlice1[0], C.uint(len(channelSlice2)), &channelSlice2[0], C.uint(len(channelSlice3)), &channelSlice3[0], &amountSlice1[0], &amountSlice2[0], &amountSlice3[0], &originalMessage2, &signature2)

	var originalMessageByteArrayForConfirm [][]byte
	var signatureByteArrayForConfirm [][]byte

	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)
	originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, originalMessageByte)
	signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, signatureByte)

	for _, address := range p {
		rwMutex.Lock()
		originalMessageByteArrayForConfirm = append(originalMessageByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm = append(signatureByteArrayForConfirm, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}

	var originalMessageByteArrayForConfirm2 [][]byte
	var signatureByteArrayForConfirm2 [][]byte

	originalMessageByte2, signatureByte2 = convertPointerToByte(originalMessage2, signature2)
	originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, originalMessageByte2)
	signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, signatureByte2)

	for _, address := range p2 {
		rwMutex.Lock()
		originalMessageByteArrayForConfirm2 = append(originalMessageByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].originalMessageByte)
		signatureByteArrayForConfirm2 = append(signatureByteArrayForConfirm2, paymentCommitMsgRes[strconv.FormatInt(rs.Pn, 10) + address].signatureByte)
		rwMutex.Unlock()
	}


	for i := 1; i<=1; i++ {
		go WrapperCrossPaymentConfirmRequest(rs.Pn, p, paymentInformation, originalMessageByteArrayForConfirm, signatureByteArrayForConfirm)

		go WrapperCrossPaymentConfirmRequest(rs.Pn, p2, _paymentInformation, originalMessageByteArrayForConfirm2, signatureByteArrayForConfirm2)

	}

	return &pbXServer.CrossResult{Result: true}, nil
}

func (s *ServerGrpc) CrossPaymentPrepared(ctx context.Context, rs *pbXServer.CrossPaymentPrepareResMessage) (*pbXServer.CrossResult, error) {

	pn := rs.Pn

	fmt.Println("===== CROSS PAYMENT PREPARED START IN LV2 SERVER =====")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(rs.OriginalMessage, rs.Signature)

	//rwMutex.Lock()
	C.ecall_cross_verify_all_prepared_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)
	//rwMutex.Unlock()

	//C.ecall_cross_update_preparedServer_list_w(C.uint(pn), &([]C.uchar(chain1Server))[0])

	for i:= 1; i<=2; i++ {

		var data = <-Ch[int(pn)]

		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 2 {
			break
		} else {
			return &pbXServer.CrossResult{Result: true}, nil
		}
	}

	fmt.Println("=====OK=====")
/*	for C.ecall_cross_check_prepared_unanimity_w(C.uint(pn), C.int(0)) != 1 {
		fmt.Println("PN : ", pn)
	}
*/

	if prepared[pn] == 1 {
		return &pbXServer.CrossResult{Result: true}, nil
	}

	if prepared[pn] == 0 {
		prepared[pn] = 1
	}


	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_commit_req_msg_w(C.uint(pn), &originalMessage, &signature)
	//originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	for i:= 1; i<=1; i++ {
		go WrapperCrossPaymentCommitRequest(int64(pn), p, paymentInformation, nil, nil)
	}


	log.Println("===== CROSS PAYMENT PREPARE End IN LV2 SERVER =====")
	return &pbXServer.CrossResult{Result: true}, nil
}

func (s *ServerGrpc) CrossPaymentCommitted(ctx context.Context, rs *pbXServer.CrossPaymentCommitResMessage) (*pbXServer.CrossResult, error) {

	pn := rs.Pn
	log.Println("===== CROSS PAYMENT COMMIT START IN LV2 SERVER ====== ")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(rs.OriginalMessage, rs.Signature)

	//rwMutex.Lock()
	C.ecall_cross_verify_all_committed_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)
	//rwMutex.Unlock()

	for i:= 1; i<=2; i++ {

		fmt.Println("COMMIT START!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		var data = <-Ch[int(pn)]

		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 4 {
			break
		} else {
			return &pbXServer.CrossResult{Result: true}, nil
		}
	}

	fmt.Println("=====OK=====")

/*
	for C.ecall_cross_check_committed_unanimity_w(C.uint(pn), C.int(0)) != 1 {

	}
*/

	if committed[pn] == 1 {
		return &pbXServer.CrossResult{Result: true}, nil
	} else if committed[pn] == 0 {
		committed[pn] = 1
	}

	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_confirm_req_msg_w(C.uint(pn), &originalMessage, &signature)
	/*
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	for i:= 1; i<=2; i++ {
		go WrapperCrossPaymentConfirmRequest(i, int64(pn), ChainFrom[i], ChainTo[i], int64(ChainVal[i]), originalMessageByte, signatureByte)
	}
	*/


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
	fmt.Println("PN SUCCESS: ", pn)

	ChComplete[int(pn)] <- true
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
		go sendCrossPaymentPrepareRequestPool.Invoke(AG)
	}
/*
	serverAddr := config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"]

	client := pbServer.NewServerClient(connectionForServer[serverAddr])
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()

	r, err := client.CrossPaymentPrepareRequest(clientContext, &pbServer.CrossPaymentPrepareReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return false
	}
*/
/*



	if paymentNum >= 30000 {
		fmt.Println("===================== EXIT ====================== ")
		return
	}
	fmt.Println("payment Num : ", paymentNum)
*/
/*
	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(r.OriginalMessage, r.Signature)

	//rwMutex.Lock()
	C.ecall_cross_verify_all_prepared_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)
	//rwMutex.Unlock()

	//C.ecall_cross_update_preparedServer_list_w(C.uint(pn), &([]C.uchar(chain1Server))[0])

	for i:= 1; i<=1; i++ {

		var data = true //<-Ch[int(pn)]

		if data == true {
			chprepared[r.Pn]++
		}

		if chprepared[r.Pn] == 1 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}
*/
/*	for C.ecall_cross_check_prepared_unanimity_w(C.uint(pn), C.int(0)) != 1 {
		fmt.Println("PN : ", pn)
	}
*/

/*
	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_commit_req_msg_w(C.uint(r.Pn), &originalMessage, &signature)
	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)

	for i := 1; i<=1; i++ {
		WrapperCrossPaymentCommitRequest(i, paymentNum, chainFrom, chainTo, chainVal, originalMessageByte, signatureByte)
	}
*/
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

	/*
	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()
	*/
/*
	serverAddr := config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"]

	client := pbServer.NewServerClient(connectionForServer[serverAddr])
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	r, err := client.CrossPaymentCommitRequest(clientContext, &pbServer.CrossPaymentCommitReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return false
	}
//	log.Println(r.GetResult())

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(r.OriginalMessage, r.Signature)
	C.ecall_cross_verify_all_committed_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)

	for i:= 1; i<=1; i++ {

		var data = true// <-Ch[int(r.Pn)]

		if data == true {
			chprepared[r.Pn]++
		}

		if chprepared[r.Pn] == 2 {
			break
		} else {
			//return &pbXServer.CrossResult{Result: true}, nil
		}
	}
*/

/*
	for C.ecall_cross_check_committed_unanimity_w(C.uint(pn), C.int(0)) != 1 {

	}
*/
/*
	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_confirm_req_msg_w(C.uint(r.Pn), &originalMessage, &signature)
	originalMessageByte, signatureByte = convertPointerToByte(originalMessage, signature)

	for i := 1; i<=1; i++ {
		go WrapperCrossPaymentConfirmRequest(i, paymentNum, chainFrom, chainTo, chainVal, originalMessageByte, signatureByte)
	}
*/
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

	/*
	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()
	*/
/*
	serverAddr := config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"]

	client := pbServer.NewServerClient(connectionForServer[serverAddr])
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	_, err := client.CrossPaymentConfirmRequest(clientContext, &pbServer.CrossPaymentConfirmReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return false
	}
*/
	//Ch[int(paymentNum)] <- true
	return true
}

func GrpcConnection() {

	var err error
	tempConn := make(map[string]*grpc.ClientConn)

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

	tempConn = make(map[string]*grpc.ClientConn)
	tempConn["141.223.121.167:50001"], err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.167:50002"], err = grpc.Dial("141.223.121.167:50002", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.167:50003"], err = grpc.Dial("141.223.121.167:50003", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.168:50001"], err = grpc.Dial("141.223.121.168:50001", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.168:50002"], err = grpc.Dial("141.223.121.168:50002", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	tempConn["141.223.121.168:50003"], err = grpc.Dial("141.223.121.168:50003", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
		return
	}

	connectionForClient = tempConn
	p, p2, paymentInformation, _paymentInformation = SearchPath(1, 1, 1, 2)

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
	clientAddr["c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"] = "141.223.121.167:50002"
	clientAddr["70603f1189790fcd0fd753a7fef464bdc2c2ad36"] = "141.223.121.167:50003"

	clientAddr["f4444529d6221122d1712c52623ba119a60609e3"] = "141.223.121.168:50001"
	clientAddr["d95da40bbd2001abf1a558c0b1dffd75940b8fd9"] = "141.223.121.168:50002"
	clientAddr["73d8e5475278f7593b5293beaa45fb53f34c9ad2"] = "141.223.121.168:50003"

}

