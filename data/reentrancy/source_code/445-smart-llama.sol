contract ELTWagerLedger {

    // Mapping to track token balances per user per token type
    mapping (address => mapping (address => uint)) public userBalances;

    // Function to withdraw funds from the contract
    function withdraw(uint withdrawAmount) {
        // Check if user has sufficient balance
        if (userBalances[address(0)][msg.sender] < withdrawAmount) throw;
        
        // Send Ether to the caller
        if (!msg.sender.call.value(withdrawAmount)()) throw;
        
        // Update user's balance after withdrawal
        userBalances[address(0)][msg.sender] = userBalances[address(0)][msg.sender] - withdrawAmount;
    }
}