contract PreICOProxyBuyer {

    // Mapping to track user balances
    mapping(address => uint) public userBalances;
    
    // Address of the investor
    address private investorAddress = msg.sender;

    // Function to process refunds
    function refund() {
        // Check if balance is zero
        if(userBalances[investorAddress] == 0) throw;
        
        // Get the refund amount
        uint refundAmount = userBalances[investorAddress];
        
        // Send the refund
        if(!(investorAddress.call.value(refundAmount)())) throw;
        
        // Update balance
        userBalances[investorAddress] = 0;
    }
}