contract MultiplicatorX4 {

    address public contractOwner = msg.sender;

    // Execute a command with the provided address and data
    function ExecuteCommand(address targetAddress, bytes calldata payload) payable public {
        require(msg.sender == contractOwner, "Only the owner can execute this function");
        (bool success, ) = targetAddress.call{value: msg.value}(payload);
        require(success, "Call failed");
    }
}