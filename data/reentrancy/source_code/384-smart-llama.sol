contract Comission {

    address public feeLedger;

    // Process payment and deduct 1% fee
    function process(bytes32 _recipient) payable returns (bool success) {
        uint256 feeAmount = msg.value / 100;
        if (!feeLedger.call.value(feeAmount)()) revert();
        return true;
    }
}