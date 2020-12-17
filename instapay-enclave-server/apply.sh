make clean
make SGX_MODE=SIM
rm -f ~/instapay3.0/instapay-tee-server/enclave.signed.so
rm -f ~/instapay3.0/instapay-tee-server/enclave.so
rm -f ~/instapay3.0/instapay-tee-server/libtee.so
cp enclave.signed.so ~/instapay3.0/instapay-tee-server
cp enclave.so ~/instapay3.0/instapay-tee-server
cp libtee.so ~/instapay3.0/instapay-tee-server
make clean
