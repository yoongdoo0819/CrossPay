function check(addr) {
	var acctBal = web3.fromWei(eth.getBalance(addr), 'ether');
	console.log(addr + ' \tbalance: ' + acctBal + ' ether');
};

function charge(addr, amount) {
	var receiver = addr;
	var sender = '0x5002873ba5e186092583e055948657ab2890075e';
	
	personal.unlockAccount(sender, '1111', 100);
	eth.sendTransaction({to:receiver, from:sender, value:web3.toWei(amount, 'ether')});

	miner.start(8);
    setTimeout(function(){ 
        miner.stop();
    }, 3000);
};
