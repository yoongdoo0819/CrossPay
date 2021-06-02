package grpc

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client -ltee

#include "app.h"
*/
/*
#include <stdio.h>

void CExample(char *p) {     // 슬라이스를 void * 타입으로 받음
	printf("zz \n");
	printf("%c\n", p[0]); // H
	printf("%s\n", p);    // Hello, world!
}
*/
import "C"

import (
	"context"

	clientPb "github.com/sslab-instapay/instapay-tee-client/proto/client"

	// "github.com/sslab-instapay/instapay-tee-client/controller"
	"sync"
	"log"
	"fmt"
	"time"
	"reflect"
	"unsafe"
)

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

//var Pn int64
var ChComplete [500000]chan bool
var chanCreateCheck = 0

var StartTime time.Time
var C_pre_yes int
var C_pre_no int
var C_post_yes int
var C_post_no int
var Addrs []string
var Amount int64

var rwMutex = new(sync.Mutex)

type ClientGrpc struct {
	clientPb.UnimplementedClientServer
}

func (s *ClientGrpc) AgreementRequest(ctx context.Context, in *clientPb.AgreeRequestsMessage) (*clientPb.AgreementResult, error) {
	//log.Println("----Receive Aggreement Request----")

//	fmt.Printf("pn %d starts \n", in.PaymentNumber)

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)


	rwMutex.Lock()
	C.ecall_go_pre_update_two_w(C.uint(in.PaymentNumber))
	rwMutex.Unlock()

	var originalMsg *C.uchar
	var signature *C.uchar
//	rwMutex.Lock()

//	C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
/*
	var Message = Message{}
	Message.messageType = 3

	Message.channel_id = 1
	Message.amount = 1
	Message.counter =0

	Message.payment_num = 1
	
	var party = "f55ba9376db959fab2af86d565325829b08ea3c4"
//	_sender := []C.uchar(party)
//	var data = []byte(party)
//	var abcd[41] C.uchar
//	abcd[0] = C.uchar(data[0])
//	abcd[1] = C.uchar(data[1])

	var Participant = Participant{}
//	C.memcpy(Participant.party, []C.uchar(&_sender[0]), 41)
	for i := 0; i < 40; i++ {
		Participant.party[i] = C.uchar(party[i])
	}


	Participant.payment_size = 1
        Participant.channel_ids[0] = 1
	Participant.payment_amount[0] = 1

	Message.participant[0] = Participant
	Message.participant[1] = Participant
	Message.participant[2] = Participant

	Message.e = 1
	_Message := (*C.uchar)(unsafe.Pointer(&Message))
*/

//	C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

	for ; ; {
		result := C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
		if result == 1 {
			fmt.Println("AG result failure!")
			return &clientPb.AgreementResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("AG ################################## ")
		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))

	}

//	rwMutex.Unlock()
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
//	var originalMsg *C.uchar = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
//	var signature *C.uchar = (*C.uchar)(unsafe.Pointer(&uSignature[0]))

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Println("sig : ", signatureStr)

	return &clientPb.AgreementResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) UpdateRequest(ctx context.Context, in *clientPb.UpdateRequestsMessage) (*clientPb.UpdateResult, error) {

//	return &clientPb.UpdateResult{Result: true}, nil

	// 채널 정보를 업데이트 한다던지 잔액을 변경.
//	log.Println("----Receive Update Request----")


	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	var originalMsg *C.uchar
	var signature *C.uchar

//	C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//	rwMutex.Lock()

	for ; ; {
		result := C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil, &originalMsg, &signature)
		if result == 1 {
			fmt.Println("UD result failure!")
			return &clientPb.UpdateResult{Result: false}, nil
		} else if result == 9999  {
			break
		}
		//fmt.Println("UD ################################## ")

		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))
	}

//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Printf("pn %d ends \n", in.PaymentNumber)
	return &clientPb.UpdateResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) ConfirmPayment(ctx context.Context, in *clientPb.ConfirmRequestsMessage) (*clientPb.ConfirmResult, error) {
//	log.Println("----ConfirmPayment Request Receive----")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])

//	C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)

//	rwMutex.Lock()
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	for ; ; {
		result := C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

		if result == 1 {
			fmt.Println("CONFIRM result failure!")
			return &clientPb.ConfirmResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("CONFIRM ################################## ")

	}

//	rwMutex.Unlock()

//	log.Println("----ConfirmPayment Request End----")

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

//	var pn = in.PaymentNumber
//	ChComplete[pn] <- true

	//fmt.Println("?")
	return &clientPb.ConfirmResult{Result: true}, nil
}

func (s *ClientGrpc) DirectChannelPayment(ctx context.Context, in *clientPb.DirectChannelPaymentMessage) (*clientPb.DirectPaymentResult, error) {
	log.Println("----Direct Channel Payment Request Receive----")

	log.Println("--- Start Byte to Pointer ---")
	originalMessagePointer, signaturePointer := convertByteToPointer(in.OriginalMessage, in.Signature)
	log.Println("--- End Byte to Pointer ---")
	var replyMessage *C.uchar
	var replySignature *C.uchar

	C.ecall_paid_w(originalMessagePointer, signaturePointer, &replyMessage, &replySignature)
	log.Println("----Direct Channel Payment Request End----")

	convertedReplyMessage, convertedReplySignature := convertPointerToByte(replyMessage, replySignature)

	defer C.free(unsafe.Pointer(replyMessage))
	defer C.free(unsafe.Pointer(replySignature))

	return &clientPb.DirectPaymentResult{Result: true, ReplyMessage: convertedReplyMessage, ReplySignature: convertedReplySignature}, nil
}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

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

//	defer C.free(unsafe.Pointer(originalMsg))
//	defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}

func convertMsgResPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(16),
		Cap:  int(16),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 16; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

	defer C.free(unsafe.Pointer(originalMsg))
	defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}
/*
 *
 *
 * InstaPay 3.0
 */

func (s *ClientGrpc) CrossPaymentPrepareClientRequest(ctx context.Context, in *clientPb.CrossPaymentPrepareReqClientMessage) (*clientPb.PrepareResult, error) {
	log.Println("----CROSS PAYMENT PREPARE START IN CLIENT----")


	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)


	rwMutex.Lock()
//	C.ecall_cross_go_pre_update_two_w(C.uint(in.PaymentNumber))
	rwMutex.Unlock()

	var originalMsg *C.uchar
	var signature *C.uchar

	Addrs = in.Addr
        Amount = in.Amount
/*
	for {

		if C_pre_yes == 1 {
			break
		} else if C_pre_yes == 2 {
			C_pre_yes = 0
			return &clientPb.PrepareResult{Result: false}, nil

		}
	}
*/
	for ; ; {
		result := C.ecall_cross_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
		if result == 1 {
			fmt.Println("PREPARE result failure!")
			return &clientPb.PrepareResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("AG ################################## ")
		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))

	}

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Println("sig : ", signatureStr)



	return &clientPb.PrepareResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) CrossPaymentCommitClientRequest(ctx context.Context, in *clientPb.CrossPaymentCommitReqClientMessage) (*clientPb.CommitResult, error) {

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	var originalMsg *C.uchar
	var signature *C.uchar

//	C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//	rwMutex.Lock()

	for ; ; {
		result := C.ecall_cross_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil, &originalMsg, &signature)
		if result == 1 {
			fmt.Println("COMMIT result failure!")
			return &clientPb.CommitResult{Result: false}, nil
		} else if result == 9999  {
			break
		}
		//fmt.Println("UD ################################## ")

		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))
	}

//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

	fmt.Println("COMMIT !!")
	return &clientPb.CommitResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil

	// 채널 정보를 업데이트 한다던지 잔액을 변경.
//	time.Sleep(time.Second * 50)
//	log.Println("----CROSS PAYMENT COMMIT START IN CLIENT----")
/*
	for {
		if C_post_yes == 1 {
			break
		}
		
		if C_post_yes == 2 {
			C_post_yes = 0
			return &clientPb.CommitResult{Result: false}, nil

		}
	}
*/
/*
	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar

//	rwMutex.Lock()
	C.ecall_cross_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	C_post_yes = 0
	log.Println("----CROSS PAYMENT COMMIT END IN CLIENT----")
	return &clientPb.CommitResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
	*/
}

func (s *ClientGrpc) CrossPaymentConfirmClientRequest(ctx context.Context, in *clientPb.CrossPaymentConfirmReqClientMessage) (*clientPb.ConfirmResult, error) {

	log.Println("----CROSS PAYMENT CONFIRM IN CLIENT----")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])

//	C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)

//	rwMutex.Lock()
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	for ; ; {
		result := C.ecall_cross_go_idle_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

		if result == 1 {
			fmt.Println("CONFIRM result failure!")
			return &clientPb.ConfirmResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("CONFIRM ################################## ")

	}

//	rwMutex.Unlock()

//	log.Println("----ConfirmPayment Request End----")

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

//	var pn = in.PaymentNumber
//	ChComplete[pn] <- true

	//fmt.Println("?")
	return &clientPb.ConfirmResult{Result: true}, nil
//	time.Sleep(time.Second * 50)

	//convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

//	rwMutex.Lock()
	//C.ecall_cross_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)
//	rwMutex.Unlock()

        log.Println("----CROSS PAYMENT CONFIRM END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)


	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	Amount = 0
	Addrs = nil
	return &clientPb.ConfirmResult{Result: true}, nil
}

func (s *ClientGrpc) CrossPaymentRefundClientRequest(ctx context.Context, in *clientPb.CrossPaymentRefundReqClientMessage) (*clientPb.RefundResult, error) {

	log.Println("----CROSS PAYMENT REFUND IN CLIENT----")
//	time.Sleep(time.Second * 50)

	//convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)
	//C.ecall_cross_refund_w(convertedOriginalMsg, convertedSignatureMsg)
        log.Println("----CROSS PAYMENT REFUND END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	Amount = 0
	Addrs = nil
	return &clientPb.RefundResult{Result: true}, nil
}


func ChanCreate() {

	fmt.Println("ChanCreate! ")

	if chanCreateCheck == 0{
		var i = 0
		for i = range ChComplete {
			//ch[i] = make(chan bool)
			ChComplete[i] = make(chan bool)
		}
		fmt.Printf("%d ChanCreate! \n", i)
	} else {
		return
	}

	chanCreateCheck = 1
}

