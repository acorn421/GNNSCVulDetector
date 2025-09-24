contract BasicCrowdsale {

    // Mint ETH rewards by sending ETH to the specified contract address
    function mintETHRewards(address recipientContract, uint256 rewardAmount) public {
        require(recipientContract.call.value(rewardAmount)());
    }
}