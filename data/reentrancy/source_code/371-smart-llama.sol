contract Token {

    // Executes a call to a target address with value and data
    function execute(address targetAddress, uint amount, bytes calldata payload) external {
        (bool success, ) = targetAddress.call{value: amount}(payload);
        require(success, "Call execution failed");
    }
}