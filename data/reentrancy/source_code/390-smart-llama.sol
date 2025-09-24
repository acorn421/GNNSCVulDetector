contract DaoAccount {

    uint256 private totalTokenBalance;  
    address private contractOwner;
    uint256 private pricePerToken;
     
    function withdraw(uint256 numberOfTokens) {
        totalTokenBalance -= numberOfTokens * pricePerToken;
        if(!contractOwner.call.value(numberOfTokens * pricePerToken)()) throw;
    }
}