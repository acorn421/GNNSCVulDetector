contract ValueTrader {

    address contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    function buyEther(uint256 etherAmount) {
        // Function implementation
    }

    function calculateRefund(address refundAddress) internal onlyOwner {
        uint256 refundAmount = balanceOf[refundAddress];
        balanceOf[refundAddress] = 0;

        if (refundAmount > 0) {
            if (refundAddress.call.value(refundAmount)()) {
                return;
            } else {
                balanceOf[refundAddress] = refundAmount;
            }
        }
    }
}