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


	//"github.com/sslab-instapay/instapay-tee-x-server/repository"
	pbServer "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	//pbClient "github.com/sslab-instapay/instapay-tee-x-server/proto/client"
	pbXServer"github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	//"unsafe"
	//"reflect"
)

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
	pbXServer.UnimplementedCross_ServerServer
}

var Ch [100000]chan bool
var ChComplete [100000]chan bool
//var Ch chan bool = make(chan bool)
//var Ch = make(map[int](chan bool), 3)
var chprepared [100000]int
var chanCreateCheck = 0

var prepared [100000]int
var committed [100000]int
var timer [100000]int

var rwMutex = new(sync.RWMutex)
var StartTime time.Time

var ChainFrom [4]string
var ChainTo   [4]string
var ChainVal  [4]int

var StartTime1 time.Time
var StartTime2 time.Time
var StartTime3 time.Time


func StartGrpcServer() {

	ChanCreate()
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


func (s *ServerGrpc) CrossPaymentPrepared(ctx context.Context, rs *pbXServer.CrossPaymentPrepareResMessage) (*pbXServer.CrossResult, error) {

	pn := rs.Pn

	fmt.Println("===== CROSS PAYMENT PREPARED START IN LV2 SERVER =====")

	/*
	if pn == 111 {
		fmt.Println("========= SERVER 1 ========")
		elapsedTime1 := time.Since(StartTime1)
		fmt.Println("execution time : ", elapsedTime1.Seconds())
		fmt.Printf("execution time : %s", elapsedTime1)

	} else if pn == 222 {
		fmt.Println("======== SERVER 2 ========")
		elapsedTime2 := time.Since(StartTime2)
		fmt.Println("execution time : ", elapsedTime2.Seconds())
		fmt.Printf("execution time : %s", elapsedTime2)

	} else if pn == 333 {
		fmt.Println("====== SERVER 3 =======")
		elapsedTime3 := time.Since(StartTime3)
		fmt.Println("execution time : ", elapsedTime3.Seconds())
		fmt.Printf("execution time : %s", elapsedTime3)
	}
	*/


	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(rs.OriginalMessage, rs.Signature)

	rwMutex.Lock()
	C.ecall_cross_verify_all_prepared_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)

	rwMutex.Unlock()
	//fmt.Printf("PN %d ALL PREPARED MSG : %d", pn, is_verified)

	//chain1Server := "chain1Server"
	//C.ecall_cross_update_preparedServer_list_w(C.uint(pn), &([]C.uchar(chain1Server))[0])

	fmt.Println("PN : ", pn)
	for i:= 1; i<=3; i++ {

		var data = <-Ch[int(pn)]

		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 3 {
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
	fmt.Println("PN SUCCESS: ", pn)

	if prepared[pn] == 1 {
		return &pbXServer.CrossResult{Result: true}, nil
	}

	if prepared[pn] == 0 {
		prepared[pn] = 1
	}


	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_cross_create_all_commit_req_msg_w(C.uint(pn), &originalMessage, &signature)
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	for i:= 1; i<=3; i++ {
		go WrapperCrossPaymentCommitRequest(i, int64(pn), ChainFrom[i], ChainTo[i], int64(ChainVal[i]), originalMessageByte, signatureByte)
	}


	log.Println("===== CROSS PAYMENT PREPARE End IN LV2 SERVER =====")
	return &pbXServer.CrossResult{Result: true}, nil
}

func (s *ServerGrpc) CrossPaymentCommitted(ctx context.Context, rs *pbXServer.CrossPaymentCommitResMessage) (*pbXServer.CrossResult, error) {

	pn := rs.Pn
/*
	if pn == 111 {
		fmt.Println("========= COMMIT SERVER 1 ========")
		elapsedTime1 := time.Since(StartTime1)
		fmt.Println("execution time : ", elapsedTime1.Seconds())
		fmt.Printf("execution time : %s", elapsedTime1)

	} else if pn == 222 {
		fmt.Println("======== COMMIT SERVER 2 ========")
		elapsedTime2 := time.Since(StartTime2)
		fmt.Println("execution time : ", elapsedTime2.Seconds())
		fmt.Printf("execution time : %s", elapsedTime2)

	} else if pn == 333 {
		fmt.Println("====== COMMIT SERVER 3 =======")
		elapsedTime3 := time.Since(StartTime3)
		fmt.Println("execution time : ", elapsedTime3.Seconds())
		fmt.Printf("execution time : %s", elapsedTime3)

	}
*/

	log.Println("===== CROSS PAYMENT COMMIT START IN LV2 SERVER ====== ")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(rs.OriginalMessage, rs.Signature)


	rwMutex.Lock()
	C.ecall_cross_verify_all_committed_res_msg_w(convertedOriginalMsg, convertedSignatureMsg)
	rwMutex.Unlock()

	fmt.Println("PN : ", pn)
	for i:= 1; i<=3; i++ {

		fmt.Println("COMMIT START!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		var data = <-Ch[int(pn)]

		if data == true {
			chprepared[pn]++
		}

		if chprepared[pn] == 6 {
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
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	for i:= 1; i<=3; i++ {
		go WrapperCrossPaymentConfirmRequest(i, int64(pn), ChainFrom[i], ChainTo[i], int64(ChainVal[i]), originalMessageByte, signatureByte)
	}


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

	//ChComplete[int(pn)] <- true
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
}

func WrapperCrossPaymentPrepareRequest(index int, paymentNum int64, chainFrom string, chainTo string, chainVal int64, originalMessageByte []byte, signatureByte []byte) {

	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()

	client := pbServer.NewServerClient(connectionForChain)
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	r, err := client.CrossPaymentPrepareRequest(clientContext, &pbServer.CrossPaymentPrepareReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(r.GetResult())

	fmt.Println("payment Num : ", paymentNum)
	Ch[int(paymentNum)] <- true

}

func WrapperCrossPaymentCommitRequest(index int, paymentNum int64, chainFrom string, chainTo string, chainVal int64, originalMessageByte []byte, signatureByte []byte) {

	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()

	client := pbServer.NewServerClient(connectionForChain)
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	r, err := client.CrossPaymentCommitRequest(clientContext, &pbServer.CrossPaymentCommitReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(r.GetResult())

	fmt.Println("payment Num : ", paymentNum)
	Ch[int(paymentNum)] <- true
}

func WrapperCrossPaymentConfirmRequest(index int, paymentNum int64, chainFrom string, chainTo string, chainVal int64, originalMessageByte []byte, signatureByte []byte) {

	connectionForChain, err := grpc.Dial(config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcHost"] + ":" + config.EthereumConfig["chain" + strconv.Itoa(index) + "ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		return
	}

	defer connectionForChain.Close()

	client := pbServer.NewServerClient(connectionForChain)
	clientContext, cancel := context.WithTimeout(context.Background(), time.Second*180)
	defer cancel()


	r, err := client.CrossPaymentConfirmRequest(clientContext, &pbServer.CrossPaymentConfirmReqMessage{Pn: paymentNum, From : chainFrom, To : chainTo, Amount: chainVal, OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(r.GetResult())

	fmt.Println("payment Num : ", paymentNum)
	//Ch[int(paymentNum)] <- true
}
