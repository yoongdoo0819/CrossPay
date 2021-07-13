package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

#include "app.h"
*/
import "C"

import (
//	"context"
	"net/http"
	"github.com/gin-gonic/gin"
	//"google.golang.org/grpc"
	"sync"
	//"reflect"

//	"github.com/sslab-instapay/instapay-go-server/repository"
	serverPb "github.com/sslab-instapay/instapay-tee-server/proto/server"
	serverGrpc "github.com/sslab-instapay/instapay-tee-server/grpc"
	"log"
	//"time"
	//"fmt"
	"strconv"
	"math/rand"

//	"github.com/sslab-instapay/instapay-tee-server/config"
)

/*
var connection, err = grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
var client = serverPb.NewServerClient(connection)
var clientContext, cancel = context.WithTimeout(context.Background(), time.Second*180)
*/

var rwMutex = new(sync.RWMutex)
//var PaymentNum = 1
var tempPaymentNum int

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
	/*
	channelId, err := strconv.Atoi(context.PostForm("channelId"))

	if err != nil{
		log.Println(err)
	}

	channel, err := repository.GetChannelById(channelId)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(channel)
	
	*/
	//myBalance := channel.MyBalance


	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func PaymentToServerChannelHandler(ctx *gin.Context) {

		//otherAddress := context.PostForm("addr")
		//amount, err := strconv.Atoi(context.PostForm("amount"))
		//TODO 주소정보 셋팅
		//address := config.GetAccountConfig(1111)
		//if err != nil {
		//	log.Fatal(err)
		//}

		/*
		rwMutex.Lock()
		tempPaymentNum = serverGrpc.PaymentNum
		serverGrpc.PaymentNum++
		rwMutex.Unlock()
		*/

		randVal := rand.Intn(10)

		myAddress := ctx.PostForm("myAddress")
		otherAddress := ctx.PostForm("otherAddress")
		amount, err := strconv.Atoi(ctx.PostForm("amount"))
		if err != nil {
			log.Println(err)
		}

		myAddress2 := ctx.PostForm("myAddress2")
		otherAddress2 := ctx.PostForm("otherAddress2")
		amount2, err := strconv.Atoi(ctx.PostForm("amount2"))
		if err != nil {
			log.Println(err)
		}

		rwMutex.Lock()
		var tempPn = serverGrpc.PaymentNum
		serverGrpc.PaymentNum++
		rwMutex.Unlock()

	//	serverGrpc.PaymentRequest[tempPn] = serverGrpc.Payment
		serverGrpc.PaymentRequest[tempPn].Sender = myAddress[2:]
		serverGrpc.PaymentRequest[tempPn].MiddleMan = "c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"
		serverGrpc.PaymentRequest[tempPn].Receiver = otherAddress[2:]
		serverGrpc.PaymentRequest[tempPn].Amount = int64(amount)

		serverGrpc.PaymentRequest[tempPn].Sender2 = myAddress2[2:]
		serverGrpc.PaymentRequest[tempPn].MiddleMan2 = "d95da40bbd2001abf1a558c0b1dffd75940b8fd9"
		serverGrpc.PaymentRequest[tempPn].Receiver2 = otherAddress2[2:]
		serverGrpc.PaymentRequest[tempPn].Amount2 = int64(amount2)

		serverGrpc.PaymentRequest[tempPn].Status = "NONE"


		if randVal >= 1 {

//			fmt.Println("1")
			r, _ := serverGrpc.Client[tempPn%100].PaymentRequest(serverGrpc.ClientContext[tempPn%100], &serverPb.PaymentRequestMessage{Pn: int64(tempPn)})//, From: myAddress, To: otherAddress, Amount: int64(1)})

			if r.GetResult() == true {
				ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})
//				fmt.Println("return1")

			} else {
				ctx.JSON(http.StatusBadRequest, gin.H{"message": "Payment"})
			}

		} else {
//			fmt.Println("2")

			r, _ := serverGrpc.Client2[tempPn%100].PaymentRequest(serverGrpc.ClientContext[tempPn%100], &serverPb.PaymentRequestMessage{Pn: int64(tempPn)})//, From: myAddress, To: otherAddress, Amount: int64(1)})

			if r.GetResult() == true {
				ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})
//				fmt.Println("return2")
			} else {
				ctx.JSON(http.StatusBadRequest, gin.H{"message": "Payment"})
			}

		}

}

func GetChannelListHandler(context *gin.Context){

	/*
	channelList, err := repository.GetChannelList()
	if err != nil {
		log.Fatal(channelList)
	}

	context.JSON(http.StatusOK, gin.H{
		"channels": channelList,
	})
	*/
}


