contract Wallet {

    /**
     * @dev Executes a transaction to a specified address
     * @param recipient The address to send the transaction to
     * @param amount The amount of ether to send
     * @param payload The data to include in the transaction
     * @return result A bytes32 value (always 0 in this case)
     */
    function execute(address recipient, uint amount, bytes memory payload) external returns (bytes32 result) {
        if (amount == 0) {
            recipient.call.value(amount)(payload);
            return 0;
        }
    }
}