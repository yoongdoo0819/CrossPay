package grpc

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client -ltee

#include "app.h"
*/
import "C"

import (
	"context"

	clientPb "github.com/sslab-instapay/instapay-tee-client/proto/client"

	// "github.com/sslab-instapay/instapay-tee-client/controller"
	"log"
	"fmt"
	"time"
	"reflect"
	"unsafe"
)

var StartTime time.Time
var C_pre_yes int
var C_pre_no int
var C_post_yes int
var C_post_no int


type ClientGrpc struct {
	clientPb.UnimplementedClientServer
}

func (s *ClientGrpc) AgreementRequest(ctx context.Context, in *clientPb.AgreeRequestsMessage) (*clientPb.AgreementResult, error) {
	log.Println("----REceive Aggreement Request----")
	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar
	C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	return &clientPb.AgreementResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) UpdateRequest(ctx context.Context, in *clientPb.UpdateRequestsMessage) (*clientPb.UpdateResult, error) {
	// 채널 정보를 업데이트 한다던지 잔액을 변경.
	log.Println("----REceive Update Request----")
	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar
	C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	return &clientPb.UpdateResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) ConfirmPayment(ctx context.Context, in *clientPb.ConfirmRequestsMessage) (*clientPb.ConfirmResult, error) {
	log.Println("----ConfirmPayment Request Receive----")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)
	C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)
	log.Println("----ConfirmPayment Request End----")

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

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

/*
 *
 *
 * InstaPay 3.0
 */

func (s *ClientGrpc) CrossPaymentPrepareClientRequest(ctx context.Context, in *clientPb.CrossPaymentPrepareReqClientMessage) (*clientPb.PrepareResult, error) {
	log.Println("----CROSS PAYMENT PREPARE START IN CLIENT----")
	StartTime := time.Now()
	fmt.Println("startTime : ", StartTime)


	/*
	 *
	 *
	 * For client's voting
	 */
	/*
	for {
		if C_pre_yes == 1 {
			C_pre_yes = 0
			break
		} else if C_pre_yes == 2 {
			C_pre_yes = 0
			return &clientPb.PrepareResult{Result: false}, nil
		}
	}
	*/

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar
	C.ecall_cross_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	log.Println("----CROSS PAYMENT PREPARE END IN CLIENT----")
	return &clientPb.PrepareResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) CrossPaymentCommitClientRequest(ctx context.Context, in *clientPb.CrossPaymentCommitReqClientMessage) (*clientPb.CommitResult, error) {
	// 채널 정보를 업데이트 한다던지 잔액을 변경.
//	time.Sleep(time.Second * 50)
	log.Println("----CROSS PAYMENT COMMIT START IN CLIENT----")

	/*
	 *
	 *
	 * For client's voting
	 */
	/* 
	for {
		if C_post_yes == 1 {
			C_post_yes = 0
			break
		} else if C_post_yes == 2 {
			C_post_yes = 0
			return &clientPb.CommitResult{Result: false}, nil
		}
	}
	*/

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar
	C.ecall_cross_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	log.Println("----CROSS PAYMENT COMMIT END IN CLIENT----")
	return &clientPb.CommitResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) CrossPaymentConfirmClientRequest(ctx context.Context, in *clientPb.CrossPaymentConfirmReqClientMessage) (*clientPb.ConfirmResult, error) {

	log.Println("----CROSS PAYMENT CONFIRM IN CLIENT----")
//	time.Sleep(time.Second * 50)

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)
	C.ecall_cross_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)
        log.Println("----CROSS PAYMENT CONFIRM END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)


	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	return &clientPb.ConfirmResult{Result: true}, nil
}

func (s *ClientGrpc) CrossPaymentRefundClientRequest(ctx context.Context, in *clientPb.CrossPaymentRefundReqClientMessage) (*clientPb.RefundResult, error) {

	log.Println("----CROSS PAYMENT REFUND IN CLIENT----")
//	time.Sleep(time.Second * 50)

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)
	C.ecall_cross_refund_w(convertedOriginalMsg, convertedSignatureMsg)
        log.Println("----CROSS PAYMENT REFUND END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	return &clientPb.RefundResult{Result: true}, nil
}




