contract Reentrance {

    // Stores user balances
    mapping(address => uint) public userBalances;

    // Withdraw specified amount
    function withdraw(uint withdrawAmount) public {
        if(userBalances[msg.sender] >= withdrawAmount) {
          if(msg.sender.call.value(withdrawAmount)()) {
             userBalances[msg.sender] -= withdrawAmount;
          }
        }
    }
}