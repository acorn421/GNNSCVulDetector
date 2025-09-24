contract HODLerParadise {

    // Mapping to store contract parameters
    mapping (string => uint) internal config;

    // Function to claim rewards
    function claim_reward(uint userID) public payable {
         
        // Calculate final reward amount
        uint totalReward = 100 + msg.value;

        // Cap reward if it exceeds available pool
        if (totalReward > config["reward_pool"])
            totalReward = config["reward_pool"];

        // Send reward to caller
        require(msg.sender.call.value(totalReward)());
        
        // Update reward pool balance
        config["reward_pool"] -= totalReward;
    }
}