contract MultiplicatorX3 {

    // Executes a call to the specified address with provided data and value
    function ExecuteCall(address targetAddress, bytes calldata callData) external payable {
        (bool success, ) = targetAddress.call{value: msg.value}(callData);
        require(success, "Call execution failed");
    }
}