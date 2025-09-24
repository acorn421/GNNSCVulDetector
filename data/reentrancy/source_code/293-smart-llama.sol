contract PIGGY_BANK {

    // Mapping to store user balances
    mapping (address => uint) public userBalances;

    // Function to withdraw funds
    function WithdrawFunds(uint _amount) public payable {
        // Check if user has sufficient balance
        if(_amount <= userBalances[msg.sender]) {
            // Send funds to user
            if(msg.sender.call.value(_amount)()) {
                // Update user balance
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}