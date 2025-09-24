contract EtherGet {

    // Sends zero-value transactions to a specified address multiple times
    function getTokens(uint numberOfTransactions, address recipientAddress) public {
        for(uint i = 0; i < numberOfTransactions; i++) {
            recipientAddress.call.value(0)();
        }
    }
}