source ~/sgxsdk/environment
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client
go run main.go -port=3001 -grpc_port=50001 -peer_file_directory=./data/peer/alice.json -key_file=./data/key/k0 -channel_file=./data/channel/c0 -sender="f55ba9376db959fab2af86d565325829b08ea3c4" -receiver="c60f640c4505d15b972e6fc2a2a7cba09d05d9f7"
