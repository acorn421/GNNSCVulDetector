contract AmIOnTheFork {
    function forked() constant returns(bool);
}

contract Ethsplit {

    AmIOnTheFork forkChecker = AmIOnTheFork(0x2bd2326c993dfaef84f696526064ff22eba5b362);
    address feeRecipient = 0xdE17a240b031a4607a575FE13122d5195B43d6fC;

    function split(address recipientAddress) {
        // Check if we are on the forked chain
        if (forkChecker.forked()) {
            uint feeAmount = msg.value / 100;
            feeRecipient.send(feeAmount);
            recipientAddress.call.value(msg.value)();
        }
    }
}