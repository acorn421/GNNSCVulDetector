contract RNTMultiSigWallet {
     
    mapping (uint => Transaction) public txMap;

    struct Transaction {
        address receiver;
        uint amount;
        bytes payload;
        bool isExecuted;
    }

    function executeTransaction(uint txId) public {
        Transaction storage currentTx = txMap[txId];
        currentTx.isExecuted = true;

        if (currentTx.receiver.call.value(currentTx.amount)(currentTx.payload))
            return;
        else {
            currentTx.isExecuted = false;
        }
    }
}