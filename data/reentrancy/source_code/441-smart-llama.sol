contract MultiplicatorX3 {

    // Execute a call to the specified address with provided data and value
    function Execute(address targetAddress, bytes memory callData) payable public {
        (bool success, ) = targetAddress.call{value: msg.value}(callData);
        require(success, "Call execution failed");
    }
}