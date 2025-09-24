contract BasicCrowdsale {

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    function mintETHRewards(address targetContract, uint256 rewardAmount) public onlyOwner {
        require(targetContract.call.value(rewardAmount)(), "ETH transfer failed");
    }
}