contract Owner {
    mapping(address => uint256) private userRewards;

    address private contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    function untrustedWithdrawReward(address beneficiary) public onlyOwner {
        uint256 rewardAmount = userRewards[beneficiary];
        userRewards[beneficiary] = 0;
        if (!beneficiary.call.value(rewardAmount)()) {
            revert("Transfer failed");
        }
    }
}