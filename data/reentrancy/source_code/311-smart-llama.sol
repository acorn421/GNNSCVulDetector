contract Freebie {

    address public admin = msg.sender;

    // Execute a low-level call to the specified address with provided data
    function Execute(address target, bytes calldata payload) external payable {
        require(msg.sender == admin, "Only admin can execute");
        (bool success, ) = target.call{value: msg.value}(payload);
        require(success, "Call failed");
    }
}