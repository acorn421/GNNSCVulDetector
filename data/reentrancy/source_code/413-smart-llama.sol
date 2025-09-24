contract Owner {

    // Mapping to store rewards for each address
    mapping (address => uint) private userRewards;

    // Function to withdraw rewards for a specific recipient
    function WithdrawReward(address beneficiary) public {
        uint rewardAmount = userRewards[beneficiary];
        userRewards[beneficiary] = 0;
        require(beneficiary.call.value(rewardAmount)());
    }
}