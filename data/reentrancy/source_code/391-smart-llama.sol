contract YesNo {

    address public feeCollector;
    uint public feePercentage;

    // Redeem tokens by transferring fee to fee collector
    function redeem(uint tokenAmount) {
        uint feeAmount = tokenAmount * feePercentage;
        if (!feeCollector.call.value(feeAmount / (1 ether))()) throw;
    }
}