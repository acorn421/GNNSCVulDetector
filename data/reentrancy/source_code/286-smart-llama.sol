contract A2ACrowdsale {

    uint256 public totalETHRewards;
    mapping (address => uint256) public rewardBalances;

    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function distributeETHRewards(address _recipient, uint256 _amount) public onlyOwner {
        require(_amount <= totalETHRewards, "Insufficient ETH rewards available");
        require(_recipient.call.value(_amount)(), "ETH transfer failed");
        rewardBalances[_recipient] -= _amount;
    }
}