contract dumbDAO {

    // Stores user balances
    mapping (address => uint) public userBalances;

    // Withdraw funds to specified recipient
    function withdraw(address recipient) returns (bool) {
        if (userBalances[msg.sender] == 0) { throw; }
        
        if (recipient.call.value(userBalances[msg.sender])()) {
            userBalances[msg.sender] = 0;
            return true;
        }
    }
}