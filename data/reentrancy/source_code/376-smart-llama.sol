contract EtherollCrowdfund {

    // Mapping to store the balance of each contributor
    mapping (address => uint) public contributorBalances;

    // Internal function to calculate and process refunds
    function processRefund(address _contributor) internal {
        uint refundAmount = contributorBalances[_contributor];
        contributorBalances[_contributor] = 0;

        if (refundAmount > 0) {
            if (_contributor.call.value(refundAmount)()) {
                return;
            } else {
                contributorBalances[_contributor] = refundAmount;
            }
        }
    }
}