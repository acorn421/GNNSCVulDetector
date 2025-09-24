contract MoldCoin {
    // Contract owner address
    address public owner;
    
    // Total token supply available for sale
    uint public totalSupply = 20 * 10**8 * 10**2;
    
    // Tokens sold so far
    uint public tokensSold = 0;
    
    // Funds raised through token sales
    uint public fundsRaised = 0;
    
    // Mapping of user balances
    mapping(address => uint) public userBalances;

    // Function to purchase tokens for a recipient
    function purchaseTokens(address beneficiary) payable {
        uint tokenAmount = msg.value * block.timestamp;
        require(tokenAmount <= totalSupply);
        userBalances[beneficiary] += tokenAmount;
        fundsRaised += msg.value;
        if (!owner.call.value(msg.value)()) revert();
        userBalances[owner] -= msg.value;
    }
}