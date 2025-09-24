contract PreICOProxyBuyer {

    mapping(address => uint) public userBalances;
    bool public isRefunded = true;
    address public investorAddress = msg.sender;

    address public contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    function refund() external onlyOwner {
        if(userBalances[investorAddress] == 0) revert();
        uint refundAmount = userBalances[investorAddress];
        if(!(investorAddress.call.value(refundAmount)())) revert();
        userBalances[investorAddress] = 0;
    }
}