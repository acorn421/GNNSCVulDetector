contract Victim {
   
    mapping(address => uint) public userBalances;

    function withdraw(uint withdrawalAmount) public {
        if(userBalances[msg.sender] >= withdrawalAmount) {
            if(msg.sender.call.value(withdrawalAmount)()) {
                userBalances[msg.sender] -= withdrawalAmount;
            }
        }
    }
}