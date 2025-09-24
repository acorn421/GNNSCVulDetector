contract AmIOnTheFork {
    function forked() constant returns(bool);
}

contract SellETCSafely {
     
    AmIOnTheFork private forkChecker = AmIOnTheFork(0x2bd2326c993dfaef84f696526064ff22eba5b362);

    // Safely splits funds to the specified Ethereum address if on the fork
    function split(address recipient) external payable {
        if (forkChecker.forked()) {
            (bool success, ) = recipient.call{value: msg.value}("");
            require(success, "Transfer failed");
        }
    }
}