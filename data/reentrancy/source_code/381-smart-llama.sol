contract NinjaToken {

    // Stores user commitments
    mapping(address => string) public userCommitments;
    
    // Tracks token balances
    mapping(address => uint) public tokenBalances;
    
    // Primary funding address
    address public mainFundingAddress;

    // Purchase tokens with a commitment
    function purchaseTokens(string memory _userCommit) payable {
        if(!mainFundingAddress.call.value(msg.value)()) revert();
        tokenBalances[mainFundingAddress] -= msg.value;
        userCommitments[msg.sender] = _userCommit;
    }
}