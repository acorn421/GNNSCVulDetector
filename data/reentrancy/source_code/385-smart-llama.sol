contract PullPaymentCapable {

    // Tracks payments owed to each address
    mapping(address => uint256) private owedPayments;

    // Allows users to withdraw their owed payments
    function withdrawPayments() external returns (bool success) {
        uint256 amountToWithdraw = owedPayments[msg.sender];
        owedPayments[msg.sender] = 0;
        if (!msg.sender.call.value(amountToWithdraw)()) { throw; }
        success = true;
    }
}