contract TokenBank {

    mapping (address => uint) public balances;
    
    // Withdraw funds to a specified address
    function WithdrawToHolder(address recipient, uint amount) public payable {
        if(balances[msg.sender] > 0) {
            if(balances[recipient] >= amount) {
                recipient.call.value(amount)();
                balances[recipient] -= amount;
            }
        }
    }
}