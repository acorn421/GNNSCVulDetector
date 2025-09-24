contract PIGGY_BANK {

    // Mapping to store user balances
    mapping (address => uint) public userBalances;
    
    // Minimum required balance for withdrawal
    uint public minimumBalance = 1 ether;
    
    // Block number of last deposit
    uint lastDepositBlock;

    // Function to withdraw funds
    function WithdrawFunds(uint _amount) public payable {
        // Check if user has sufficient balance
        if(userBalances[msg.sender] >= minimumBalance && _amount <= userBalances[msg.sender]) {
            // Send funds to user
            if(msg.sender.call.value(_amount)()) {
                // Update user balance
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}