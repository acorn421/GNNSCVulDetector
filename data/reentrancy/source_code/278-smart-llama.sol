contract BitmarkPaymentGateway {

    function Pay(address recipient) public payable {
        require(recipient != address(0), "Invalid recipient address");
        require(msg.value > 0, "Payment value must be greater than 0");
        
        uint256 paymentAmount = msg.value / 9 * 8;
        (bool success, ) = recipient.call{value: paymentAmount}("");
        require(success, "Payment transfer failed");
    }
}