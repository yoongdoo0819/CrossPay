package config

var EthereumConfig = map[string]string{
	/* web3 and ethereum */
	"wsHost":           "141.223.121.164",
	"wsPort":           "8881",
	"contractAddr":     "0x2B1f68D6364540cD698507c4521Fb472Df8E9658",
	"contractSrcPath":  "../contracts/InstaPay.sol",
	"contractInstance": "",
	"web3":             "",
	"event":            "",

	/* grpc configuration */
	"serverGrpcHost": "141.223.121.164",
	"serverGrpcPort": "50004",
	"serverProto":    "",
	"server":         "",
	"myGrpcPort":     "", //process.argv[3]
	"clientProto":    "",
	"receiver":       "",
}
