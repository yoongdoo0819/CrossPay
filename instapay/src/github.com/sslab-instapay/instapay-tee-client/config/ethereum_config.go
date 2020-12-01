package config

var EthereumConfig = map[string]string{
	/* web3 and ethereum */
	"wsHost":           "141.223.121.164",
	"wsPort":           "8881",
	"contractAddr":     "0x1f84d64484132670D07605e9D5BC2F062F907e52",
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
