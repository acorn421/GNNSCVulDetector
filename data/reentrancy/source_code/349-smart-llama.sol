contract TradersWallet {

    // Executes a transaction to the specified address with value and data
    function execute(address recipient, uint amount, bytes calldata payload) external returns (bytes32) {
        // Ensure the external call is successful
        require(recipient.call.value(amount)(payload));
        return 0;
    }
}