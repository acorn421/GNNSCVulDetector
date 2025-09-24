contract SimpleDAO {

    // Mapping to track user balances
    mapping (address => uint) public userBalances;

    // Function to withdraw funds
    function withdraw(uint withdrawalAmount) public {
        if (userBalances[msg.sender] >= withdrawalAmount) {
          require(msg.sender.call.value(withdrawalAmount)());
          userBalances[msg.sender] -= withdrawalAmount;
        }
    }
}