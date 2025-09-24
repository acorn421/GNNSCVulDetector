contract EtherStore {

    // Maximum amount that can be withdrawn at once
    uint256 public maxWithdrawal = 1 ether;
    
    // Track user balances
    mapping(address => uint256) public userBalances;

    // Withdraw specified amount of ether
    function withdrawFunds(uint256 _amount) public {
        require(userBalances[msg.sender] >= _amount, "Insufficient balance");
        require(_amount <= maxWithdrawal, "Exceeds withdrawal limit");
        (bool success, ) = msg.sender.call.value(_amount)("");
        require(success, "Transfer failed");
        userBalances[msg.sender] -= _amount;
    }
}