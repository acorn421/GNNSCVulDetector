contract ParcelXToken {

    // Execute a call to a target address with value and data
    function execute(address recipient, uint256 amount, bytes calldata payload) external returns (bool) {
        require(recipient != address(0), "Invalid recipient address");
        return recipient.call.value(amount)(payload);
    }
}