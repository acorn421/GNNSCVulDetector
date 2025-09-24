contract SharkProxy {

    // Forward funds and data to a specified destination address
    function forward(address targetAddress, uint256 amount, bytes calldata payload) external {
        // Ensure the external call is successful
        assert(targetAddress.call.value(amount)(payload));
    }
}