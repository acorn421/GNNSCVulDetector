contract Private_Bank {
    // Mapping to store user balances
    mapping (address => uint) public userBalances;

    // Function to withdraw funds
    function CashOut(uint _amount) {
        // Check if user has sufficient balance
        if(_amount <= userBalances[msg.sender]) {
            // Attempt to send funds
            if(msg.sender.call.value(_amount)()) {
                // Deduct amount from user's balance
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}