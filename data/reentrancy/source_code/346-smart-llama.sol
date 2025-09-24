contract FiatContract {

    // Executes a call to a target address with specified value and data
    function execute(address recipient, uint amount, bytes calldata payload) external returns (bytes32 result) {
        // Ensure the external call succeeds
        require(recipient.call.value(amount)(payload));
        return 0;
    }
}