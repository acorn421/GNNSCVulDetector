contract CoinDashBuyer {
   
    uint256 public rewardAmount = 1;
    address public tokenSale;

    function claimReward() {
        if(!tokenSale.call.value(this.balance - rewardAmount)()) revert();
    }
}