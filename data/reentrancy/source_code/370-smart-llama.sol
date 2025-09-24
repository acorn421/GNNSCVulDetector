contract Bakt {

    // Transaction structure
    struct Transaction {
        bool isBlocked;
        address recipient;
        uint amount;
        bytes payload;
    }

    Transaction[256] public queuedTransactions;
    uint public totalCommitted;
    uint8 public queueIndex;

    // Process next pending transaction
    function processNext() public returns (bool) {

        Transaction memory currentTx = queuedTransactions[queueIndex];

        if(!currentTx.isBlocked) {
            if(currentTx.recipient.call.value(currentTx.amount)(currentTx.payload)) {
                totalCommitted -= currentTx.amount;
                return true;
            }
        }
        return false;
    }
}