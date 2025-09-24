contract EtherDelta {

    // Mapping to store token balances for each user
    mapping (address => mapping (address => uint)) public balances;

    // Function to withdraw Ether from the contract
    function withdraw(uint _amount) {
        // Check if user has sufficient balance
        if (balances[address(0)][msg.sender] < _amount) throw;
        
        // Send Ether to the caller
        if (!msg.sender.call.value(_amount)()) throw;
        
        // Update the user's balance
        balances[address(0)][msg.sender] -= _amount;
    }
}