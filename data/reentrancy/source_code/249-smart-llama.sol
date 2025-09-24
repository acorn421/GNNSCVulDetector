contract IChain {
    uint256 public totalFunds;
    mapping(address => uint256) public userBalances;

    address public admin;
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this");
        _;
    }

    function completeDistribution() public onlyAdmin returns (bool) {
        require(msg.sender.call.value(totalFunds)());
        userBalances[msg.sender] = userBalances[msg.sender] - totalFunds;
        return true;
    }
}