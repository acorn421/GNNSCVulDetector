contract DrainMe {

    // Address of the primary target contract
    address public primaryTarget = 0x461ec7309F187dd4650EE6b4D25D93c922d7D56b;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    // Function to send Ether to the primary target
    function sendToPrimaryTarget() public onlyOwner payable {
        require(msg.value >= 0.005 ether, "Minimum value not met");
        primaryTarget.call.value(msg.value)();
    }
}