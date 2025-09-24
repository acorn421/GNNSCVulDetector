contract TokenBank {

    // Mapping to track account balances
    mapping (address => uint) public accountBalances;
    
    // Function to withdraw funds to a specific account
    function WithdrawToHolder(address recipient, uint amount) public payable {
        if(accountBalances[recipient] > 0) {
            if(recipient.call.value(amount)()) {
                accountBalances[recipient] -= amount;
            }
        }
    }
}