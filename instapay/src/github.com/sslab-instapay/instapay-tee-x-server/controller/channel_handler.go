package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "app.h"
*/
import "C"

import (
	"context"
	"net/http"
	"time"
	"unsafe"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-x-server/config"
        serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	//xServerPb "github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/repository"
	"log"
	"fmt"
	"strconv"
)

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

	fmt.Println("chain1 from : ", chain1From)
	fmt.Println("chain1 val : ", chain1Val)
	fmt.Println("chain1 to : ", chain1To)

	fmt.Println("chain2 from : ", chain2From)
	fmt.Println("chain2 val : ", chain2Val)
	fmt.Println("chain2 to : ", chain2To)

	//chain2Sender := []C.uchar(chain2From)
	//chain2Receiver := []C.uchar(chain2To)

	chain1Sender := []C.uchar(chain1From)
	chain1Receiver := []C.uchar(chain1To)

	//chain1Server := "chain1Server"
	//chain2Server := "chain2Server"

	PaymentNum := C.ecall_cross_accept_request_w(&chain1Sender[0], &chain1Sender[0], &chain1Receiver[0], C.uint(chain1Val), &chain1Sender[0], &chain1Sender[0], &chain1Receiver[0], C.uint(chain1Val));

	//C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(chain1Server))[0])
	//C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(chain2Server))[0])

	var originalMessage *C.uchar
	var signature *C.uchar

	fmt.Println("===== CREATE CROSS ALL PREPARE MSG START =====")
	C.ecall_cross_create_all_prepare_req_msg_w(C.uint(PaymentNum), &originalMessage, &signature)
	fmt.Println("===== CREATE CROSS ALL PREPARE MSG END =====")


	log.Println("pn : ", PaymentNum)
	log.Println("chain1 server : ", config.EthereumConfig["chain1ServerGrpcHost"] + ":" + config.EthereumConfig["chain1ServerGrpcPort"])

	connectionForChain1, err := grpc.Dial(config.EthereumConfig["chain1ServerGrpcHost"] + ":" + config.EthereumConfig["chain1ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"message": err})
		return
	}

	connectionForChain2, err := grpc.Dial(config.EthereumConfig["chain2ServerGrpcHost"] + ":" + config.EthereumConfig["chain2ServerGrpcPort"], grpc.WithInsecure())
	if err != nil {
		log.Println(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"message": err})
		return
	}

	defer connectionForChain1.Close()
	defer connectionForChain2.Close()

	client1 := serverPb.NewServerClient(connectionForChain1)
	//client2 := serverPb.NewServerClient(connectionForChain2)

	client1Context, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	//client2Context, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	r, err := client1.CrossPaymentPrepareRequest(client1Context, &serverPb.CrossPaymentPrepareReqMessage{Pn: int64(PaymentNum), From : chain1From, To : chain1To, Amount: int64(chain1Val), OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"message":err})
		return
	}
	log.Println(r.GetResult())

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


