contract PreICOProxyBuyer {

    mapping(address => uint256) public userBalances;
    bool public isRefunded = true;
    address public currentInvestor = msg.sender;

    address public contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this");
        _;
    }

    function refund() external onlyOwner {
        require(userBalances[currentInvestor] > 0, "No balance to refund");
        
        uint256 refundAmount = userBalances[currentInvestor];
        userBalances[currentInvestor] = 0;
        
        (bool success, ) = currentInvestor.call{value: refundAmount}("");
        require(success, "Refund transfer failed");
    }
}