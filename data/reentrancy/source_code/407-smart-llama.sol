contract SendBalance {

    // Mapping to store user balances
    mapping (address => uint) accountFunds;

    // Function to withdraw funds
    function withdrawBalance() {
        // Send funds to the caller
        if (!(msg.sender.call.value(accountFunds[msg.sender])())) { throw; }
        // Reset the balance after sending
        accountFunds[msg.sender] = 0;
    }
}