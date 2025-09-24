contract DividendToken {

    // Tracks points credited to each address
    mapping (address => uint) private userCredits;
    
    // Total dividends collected so far
    uint private totalDividends = 0;

    // Allows users to collect their owed dividends
    function collectOwedDividends() public returns (uint) {
        uint owedAmount = userCredits[msg.sender] / 20;
        require(msg.sender.call.value(owedAmount)());
        userCredits[msg.sender] -= owedAmount;
        totalDividends += owedAmount;
        return totalDividends;
    }
}