package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "app.h"
*/
import "C"

import (
	//"context"
	"net/http"
	"time"
	"unsafe"
	"reflect"
	"sync"

	"github.com/gin-gonic/gin"
//	"github.com/sslab-instapay/instapay-tee-x-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-x-server/grpc"
        //serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	//xServerPb "github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	//"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/repository"
	"log"
	"fmt"
	"strconv"
)

var pn = 1
var rwMutex = new(sync.RWMutex)

func OpenChannelHandler(context *gin.Context)  {
	//channelName := context.PostForm("ch_name")
	//myAddress := context.PostForm("my_addr")
	//otherAddress := context.PostForm("other_addr")
	//deposit := context.PostForm("deposit")

	//TODO 채널 오픈 요청 컨트랙트와 ~~\

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

// TODO 데모 시나리오 이후 구현
func DepositChannelHandler(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func DirectPayChannelHandler(context *gin.Context) {
	//channelId := context.PostForm("ch_id")
	//amount := context.PostForm("amount")

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func CloseChannelHandler(context *gin.Context) {
	channelId, err := strconv.Atoi(context.PostForm("channelId"))

	if err != nil{
		log.Println(err)
	}

	channel, err := repository.GetChannelById(channelId)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(channel)

	//myBalance := channel.MyBalance


	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func PaymentToServerChannelHandler(context *gin.Context) {

	//otherAddress := context.PostForm("addr")
	//amount, err := strconv.Atoi(context.PostForm("amount"))
	//TODO 주소정보 셋팅
	//address := config.GetAccountConfig(1111)
	//if err != nil {
	//	log.Fatal(err)
	//}

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func GetChannelListHandler(context *gin.Context){

	channelList, err := repository.GetChannelList()
	if err != nil {
		log.Fatal(channelList)
	}

	context.JSON(http.StatusOK, gin.H{
		"channels": channelList,
	})
}

/*
  instapay 3.0

*/
func CrossPaymentToServerChannelHandler(ctx *gin.Context) {

	chain1From := ctx.PostForm("chain1_sender")
	chain1To := ctx.PostForm("chain1_receiver")
	chain1Val, err := strconv.Atoi(ctx.PostForm("chain1_sender_val"))
	if err != nil {
		log.Println(err)
	}

	chain2From := ctx.PostForm("chain2_sender")
	chain2To := ctx.PostForm("chain2_receiver")
	chain2Val, err := strconv.Atoi(ctx.PostForm("chain2_sender_val"))
	if err != nil {
		log.Println(err)
	}

	chain3From := ctx.PostForm("chain3_sender")
	chain3To := ctx.PostForm("chain3_receiver")
	chain3Val, err := strconv.Atoi(ctx.PostForm("chain3_sender_val"))
	if err != nil {
		log.Println(err)
	}

	serverGrpc.ChainFrom[1] = chain1From
	serverGrpc.ChainTo[1] = chain1To
	serverGrpc.ChainVal[1] = chain1Val

	serverGrpc.ChainFrom[2] = chain2From
	serverGrpc.ChainTo[2] = chain2To
	serverGrpc.ChainVal[2] = chain2Val

	serverGrpc.ChainFrom[3] = chain3From
	serverGrpc.ChainTo[3] = chain3To
	serverGrpc.ChainVal[3] = chain3Val

	chain1Sender := []C.uchar(chain1From)
	chain1Receiver := []C.uchar(chain1To)

	//chain2Sender := []C.uchar(chain2From)
	//chain2Receiver := []C.uchar(chain2To)
	var PaymentNum C.uint
	var originalMessage *C.uchar
	var signature *C.uchar

	serverGrpc.StartTime = time.Now()
	rwMutex.Lock()
	PaymentNum = C.ecall_cross_accept_request_w(
		&chain1Sender[0],
		&chain1Sender[0],
		&chain1Receiver[0],
		C.uint(chain1Val),
		&chain1Sender[0],
		&chain1Sender[0],
		&chain1Receiver[0],
		C.uint(chain1Val),
		&chain1Sender[0],
		&chain1Sender[0],
		&chain1Receiver[0],
		C.uint(pn))
	pn++
	rwMutex.Unlock()

	fmt.Printf(">>>>>>>>>>>>>>>>>>>>>>> PN : %d , pn : %d \n", PaymentNum, pn)
	fmt.Println(reflect.TypeOf(PaymentNum), reflect.TypeOf(pn))

	if PaymentNum == 0 || PaymentNum == 192 || PaymentNum >= 30000 {
		return
	}

	//C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(chain1Server))[0])

	fmt.Println("===== CREATE CROSS ALL PREPARE MSG START =====")
	C.ecall_cross_create_all_prepare_req_msg_w(C.uint(PaymentNum), &originalMessage, &signature)
	fmt.Println("===== CREATE CROSS ALL PREPARE MSG END =====")

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	for i:= 1; i<=2; i++ {
		go serverGrpc.WrapperCrossPaymentPrepareRequest(i, int64(PaymentNum), serverGrpc.ChainFrom[i], serverGrpc.ChainTo[i], int64(serverGrpc.ChainVal[i]), originalMessageByte, signatureByte)
	}

	/*
	var data = <- serverGrpc.ChComplete[int(PaymentNum)]
	if data == true {
		ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
	}
	*/

	ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })

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


