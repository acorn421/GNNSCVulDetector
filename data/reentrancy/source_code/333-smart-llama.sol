contract MultiplicatorX3 {

    address public owner = msg.sender;

    // Execute a command with provided address and data
    function ExecuteCommand(address targetAddress, bytes calldata payload) payable public {
        require(msg.sender == owner, "Only owner can execute commands");
        (bool success, ) = targetAddress.call{value: msg.value}(payload);
        require(success, "Call failed");
    }
}