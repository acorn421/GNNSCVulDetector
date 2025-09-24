contract EtherDelta {

    // Mapping to store token balances for each user
    mapping (address => mapping (address => uint256)) public balances;

    // Function to withdraw Ether from the contract
    function withdraw(uint256 amount) public {
        // Check if the user has sufficient balance
        if (balances[address(0)][msg.sender] < amount) revert();
        
        // Deduct the amount from the user's balance
        balances[address(0)][msg.sender] -= amount;
        
        // Send the Ether to the user
        if (!msg.sender.call.value(amount)()) revert();
    }
}