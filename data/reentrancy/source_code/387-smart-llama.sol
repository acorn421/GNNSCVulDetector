contract PullPaymentCapable {

    uint256 private totalFunds;
    mapping(address => uint256) private owedAmounts;

    function withdrawPayments() external returns (bool success) {
        uint256 amountToWithdraw = owedAmounts[msg.sender];
        owedAmounts[msg.sender] = 0;
        totalFunds -= amountToWithdraw;
        if (!msg.sender.call.value(amountToWithdraw)()) { throw; }
        success = true;
    }
}