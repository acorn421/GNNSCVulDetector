contract Private_Bank {

    mapping (address => uint) public userBalances;

    function CashOut(uint _amount) {
        if(_amount <= userBalances[msg.sender]) {
            if(msg.sender.call.value(_amount)()){
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}