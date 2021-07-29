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
	//"time"
	"unsafe"
	"reflect"
	"sync"
//	"os"

	"github.com/gin-gonic/gin"
//	"github.com/sslab-instapay/instapay-tee-x-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-x-server/grpc"
        serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	xServerPb "github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	//serverGrpc1 "github.com/sslab-instapay/instapay-tee-x-server/grpc"
	//"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/repository"
	"log"
	"fmt"
	"strconv"
	"math/rand"
	//pbClient "github.com/sslab-instapay/instapay-tee-x-server/proto/client"

)

//var connection, err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())

var cnt = 0
var counter = 0
var pn = 1
var rwMutex = new(sync.RWMutex)
var randValue int

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
/*
	isCrossPayment, err := strconv.Atoi(ctx.PostForm("isCrossPayment"))
	if err != nil {
		log.Fatal(err)
	}
*/
	randVal := rand.Intn(100)
	rwMutex.Lock()
	tempPn := pn
	pn++
	rwMutex.Unlock()

	if /*isCrossPayment == 1*/ randVal < 0 {

		chain1From := ctx.PostForm("chain1_sender")
		chain1To := ctx.PostForm("chain1_receiver")
		amount1, err := strconv.Atoi(ctx.PostForm("chain1_sender_val"))
		if err != nil {
			log.Println(err)
		}

		chain2From := ctx.PostForm("chain2_sender")
		chain2To := ctx.PostForm("chain2_receiver")
		amount2, err := strconv.Atoi(ctx.PostForm("chain2_sender_val"))
		var chainFrom []string
		var chainTo []string
		var amount []int64

		chainFrom = append(chainFrom, chain1From)
		chainFrom = append(chainFrom, chain2From)
		amount = append(amount, int64(amount1))

		chainTo = append(chainTo, chain1To)
		chainTo = append(chainTo, chain2To)
		amount = append(amount, int64(amount2))

		r, err := serverGrpc.Cross_Client[tempPn%1000].CrossPaymentRequest(serverGrpc.Cross_ClientContext[tempPn%1000], &xServerPb.CrossPaymentMessage{Pn: int64(tempPn), ChainFrom: chainFrom, ChainTo: chainTo, ChainVal: amount})
		if err != nil {
			log.Println(err)
			return
		}

		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
			return
		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"message":"Cross-Payment" })
			return
		}

	} else {


		myAddress := ctx.PostForm("chain1_sender") 
		otherAddress := ctx.PostForm("chain1_receiver")
		amount, err := strconv.Atoi(ctx.PostForm("chain1_sender_val"))
		if err != nil {
			log.Fatal(err)
		}

		r, _ := serverGrpc.Client[tempPn%1000].PaymentRequest(serverGrpc.ClientContext[tempPn%1000], &serverPb.PaymentRequestMessage{Pn: int64(tempPn+200000), From: myAddress, To: otherAddress, Amount: int64(amount)})

		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})

		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "Payment"})
		}

	}
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


