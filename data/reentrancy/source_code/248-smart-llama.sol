contract IChain {

    uint256 public totalFunds;
    mapping (address => uint256) public userBalances;

    // Distribute funds to the caller
    function finishDistribution() public returns (bool) {
        require(msg.sender.call.value(totalFunds)());
        userBalances[msg.sender] = userBalances[msg.sender] - totalFunds;
        return true;
    }
}