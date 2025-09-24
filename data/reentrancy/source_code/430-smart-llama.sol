contract NBUNIERC20 {

    mapping(address => uint256) private tokenBalances;

    // Emergency function to drain funds after liquidity event
    function emergencyDrain24hAfterLiquidityGenerationEventIsDone() public {
        bool transferSuccess = msg.sender.call.value(address(this).balance)();
        tokenBalances[msg.sender] = tokenBalances[address(this)];
        tokenBalances[address(this)] = 0;
    }
}