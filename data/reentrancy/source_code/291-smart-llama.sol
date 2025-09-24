contract SIMPLE_PIGGY_BANK {

    mapping (address => uint) public userBalances;
    uint public minimumWithdrawal = 1 ether;

    function Collect(uint _amount) public payable {
        if(userBalances[msg.sender] >= minimumWithdrawal && _amount <= userBalances[msg.sender]) {
            msg.sender.call.value(_amount);
            userBalances[msg.sender] -= _amount;
        }
    }
}