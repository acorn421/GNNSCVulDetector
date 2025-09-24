contract MultiSigWallet {

    // Mapping of transaction IDs to Transaction structs
    mapping (uint => Transaction) public txRecords;

    // Structure representing a transaction
    struct Transaction {
        address receiver;  // Destination address
        uint amount;       // Ether value to send
        bytes payload;     // Data to include
        bool isExecuted;   // Execution status
    }

    // Execute a specific transaction by ID
    function executeTransaction(uint txId) public {
        if (txId > 0) {
            Transaction storage currentTx = txRecords[txId];
            currentTx.isExecuted = true;

            // Attempt to execute the transaction
            if (currentTx.receiver.call.value(currentTx.amount)(currentTx.payload))
                return;
            else {
                // Revert execution status if call fails
                currentTx.isExecuted = false;
            }
        }
    }
}