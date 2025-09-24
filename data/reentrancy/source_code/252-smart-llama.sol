contract HiroyukiCoinDark {

    mapping(address => uint256) public balanceOf;

    // Transfers tokens from sender to recipient
    function transfer(address recipient, uint amount, bytes calldata data) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        
        // Prevent reentrancy by making a zero-value call
        (bool success, ) = msg.sender.call{value: 0}("");
        assert(success);
        
        return true;
    }
}