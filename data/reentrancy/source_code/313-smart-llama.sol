contract PrivateBank {

    // Stores user balances
    mapping (address => uint) public userBalances;

    // Allows users to withdraw funds
    function CashOut(uint _amount) {
        if(_amount <= userBalances[msg.sender]) {
            if(msg.sender.call.value(_amount)()){
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}