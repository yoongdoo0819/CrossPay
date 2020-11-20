make clean
make
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-server/enclave.signed.so
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-server/enclave.so
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-server/libtee.so
cp enclave.signed.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-server
cp enclave.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-server
cp libtee.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-server
make clean