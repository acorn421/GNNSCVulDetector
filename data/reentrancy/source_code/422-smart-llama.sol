contract SimpleDAO {

    // Tracks user balances
    mapping (address => uint) public userBalances;

    // Allows users to withdraw funds
    function withdraw(uint withdrawalAmount) {
        if (userBalances[msg.sender] >= withdrawalAmount) {
            msg.sender.call.value(withdrawalAmount)();
            userBalances[msg.sender] -= withdrawalAmount;
        }
    }
}