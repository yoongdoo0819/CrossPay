package controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sslab-instapay/instapay-tee-x-server/config"
        serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
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

	chain1Sender := ctx.PostForm("chain1_sender")
	chain1Receiver := ctx.PostForm("chain1_receiver")
	chain1SenderVal := ctx.PostForm("chain1_sender_val")

	chain2Sender := ctx.PostForm("chain2_sender")
	chain2Receiver := ctx.PostForm("chain2_receiver")
	chain2SenderVal, err := strconv.Atoi(ctx.PostForm("chain2_sender_val"))
	if err != nil {
		log.Println(err)
	}

	fmt.Println("chain1 sender : ", chain1Sender)
	fmt.Println("chain1 sender val : ", chain1SenderVal)
	fmt.Println("chain1 receiver : ", chain1Receiver)

	fmt.Println("chain2 sender : ", chain2Sender)
	fmt.Println("chain2 sender val : ", chain2SenderVal)
	fmt.Println("chain2 receiver : ", chain2Receiver)


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

	//client1 := serverPb.NewServerClient(connectionForChain1)
	client2 := serverPb.NewServerClient(connectionForChain2)

	//client1Context, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()
	client2Context, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := client2.PaymentRequest(client2Context, &serverPb.PaymentRequestMessage{From : chain2Sender, To : chain2Receiver, Amount: int64(chain2SenderVal)})
	if err != nil {
		log.Println(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"message":err})
		return
	}
	log.Println(r.GetResult())

	ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
}





