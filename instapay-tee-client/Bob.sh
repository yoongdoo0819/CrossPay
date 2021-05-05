source ~/sgxsdk/environment
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/
go run main.go -port=3002 -grpc_port=50002 -peer_file_directory=./data/peer/bob.json -key_file=./data/key/k1 -channel_file=./data/channel/c1 -previous_sender="f55ba9376db959fab2af86d565325829b08ea3c4" -sender="c60f640c4505d15b972e6fc2a2a7cba09d05d9f7" -receiver="70603f1189790fcd0fd753a7fef464bdc2c2ad36"
