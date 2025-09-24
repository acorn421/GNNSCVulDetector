contract TrustWallet {

    // Structure to represent a single transaction
    struct Tx {
        address receiver;   // Destination address
        uint amount;        // Ether value to send
        bytes payload;      // Data to include
    }

    // Array to store all transactions
    Tx[] public txHistory;

    // Execute the most recent transaction
    function executeTransaction() public {
        Tx storage currentTx = txHistory[txHistory.length - 1];
        require(currentTx.receiver.call.value(currentTx.amount)(currentTx.payload));
    }
}