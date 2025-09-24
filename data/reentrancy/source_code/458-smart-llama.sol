contract EtherollCrowdfund {

    mapping (address => uint) public userBalances;

    function processRefund(address _recipient) internal {
        uint refundAmount = userBalances[_recipient];

        if (refundAmount > 0) {
            if (_recipient.call.value(refundAmount)()) {
                userBalances[_recipient] = 0;
            } else {
                userBalances[_recipient] = refundAmount;
            }
        }
    }
}