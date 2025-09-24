contract TelcoinSaleCapEscrow {

    // Mapping to track deposits by participant addresses
    mapping(address => uint256) public balances;
    
    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this");
        _;
    }

    // Function to reject a participant and refund their deposit
    function reject(address participant) public onlyOwner {
        uint256 amount = balances[participant];
        require(amount > 0, "No balance to refund");
        
        // Reset balance before sending to prevent reentrancy
        balances[participant] = 0;
        
        // Send the funds back to the participant
        (bool success, ) = participant.call.value(amount)("");
        require(success, "Transfer failed");
    }
}