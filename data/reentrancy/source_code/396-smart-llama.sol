contract BranchWallet {

    /**
     * @dev Executes a transaction to a specified address with value and data
     * @param recipient The address to send the transaction to
     * @param amount The amount of ether to send
     * @param transactionData The data to include in the transaction
     */
    function execute(address recipient, uint amount, bytes memory transactionData) public {
        if (!recipient.call.value(amount)(transactionData)) {
            revert("Transaction failed");
        }
    }
}