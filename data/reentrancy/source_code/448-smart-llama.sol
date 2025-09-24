contract BoomerangLiquidity {

    struct Investor {
        address walletAddress;
        uint rewardAmount;
    }
    Investor[] public investors;
    uint public currentPayoutIndex = 0;

    function payout() public {
        uint contractBalance = address(this).balance;
        require(contractBalance > 1);
        uint initialInvestment = contractBalance / 2;
        contractBalance -= initialInvestment;

        while (contractBalance > 0) {
            uint rewardToSend = contractBalance < investors[currentPayoutIndex].rewardAmount ? contractBalance : investors[currentPayoutIndex].rewardAmount;

            if(rewardToSend > 0){
                investors[currentPayoutIndex].walletAddress.call.value(rewardToSend).gas(1000000)();
                investors[currentPayoutIndex].rewardAmount -= rewardToSend;
                contractBalance -= rewardToSend;
            }
        }
    }
}