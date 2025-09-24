contract XToken {
    mapping(address => uint256) public tokenBalances;
    
    function transfer(
        address recipient, 
        uint256 amount, 
        bytes memory payload, 
        string memory callback
    ) public returns (bool) {
        require(tokenBalances[msg.sender] >= amount, "Insufficient balance");
        
        (bool transferSuccess,) = recipient.call(
            abi.encodeWithSignature(callback, msg.sender, amount, payload)
        );
        require(transferSuccess, "Token transfer failed");
        
        tokenBalances[msg.sender] -= amount;
        tokenBalances[recipient] += amount;
        
        return true;
    }
}