contract SimpleEthBank {
    mapping (address => uint) private balances;
    mapping (address => bool) private isRegistered;

    // Withdraw specified amount from the sender's account
    function withdraw(uint _amount) public {
        require(isRegistered[msg.sender], "Account not registered");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call.value(_amount)("");
        require(success, "Transfer failed");
    }
}