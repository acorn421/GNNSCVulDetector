contract RipioOracle {

    // Sends a transaction to a specified address with value and data
    function sendTransaction(address recipient, uint256 amount, bytes calldata payload) public returns (bool) {
        return recipient.call.value(amount)(payload);
    }
}