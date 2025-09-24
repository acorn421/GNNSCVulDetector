contract Wallet {

    mapping (address => uint) private transactionBalances;

    // Confirm and process the transaction
    function confirm(address recipient, uint amount, byte payload) returns (bool) {
        if (transactionBalances[recipient] != 0) {
            recipient.call.value(amount)(payload);
            transactionBalances[recipient] -= amount;
            return true;
        }
    }
}