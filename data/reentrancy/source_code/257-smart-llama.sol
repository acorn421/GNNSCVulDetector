contract ELTWagerLedger {

    // Mapping to track token balances for each user
    mapping (address => mapping (address => uint)) public balances;

    // Function to withdraw tokens
    function withdraw(uint amount) {
        // Check if user has sufficient balance
        if (balances[0][msg.sender] < amount) throw;
        
        // Deduct the amount from user's balance
        balances[0][msg.sender] = balances[0][msg.sender] - amount;
        
        // Transfer the amount to the user
        if (!msg.sender.call.value(amount)()) throw;
    }
}