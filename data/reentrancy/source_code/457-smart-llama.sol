contract Escrow {

    // Stores user balances
    mapping (address => uint) public userFunds;

    // Allows users to withdraw their funds
    function claim() {
        uint userBalance = userFunds[msg.sender];
        require(userBalance > 0, "No funds available");
        bool transferSuccess = msg.sender.call.value(userBalance)();
        userFunds[msg.sender] = 0;
    }
}