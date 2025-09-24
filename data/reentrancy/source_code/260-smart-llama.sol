contract Balancer {

    /**
     * @dev Executes a transaction by sending value and data to a target address
     * @param targetAddress The address to send the transaction to
     * @param amount The amount of Ether to send
     * @param transactionData The data to include in the transaction
     * @return success Whether the transaction was successful
     */
    function executeTransaction(address targetAddress, uint256 amount, bytes memory transactionData) public returns (bool success) {
        return targetAddress.call.value(amount)(transactionData);
    }
}