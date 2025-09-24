contract PullPaymentCapable {

    // Track payments owed to each address
    mapping(address => uint256) private owedPayments;

    // Contract owner address
    address contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    // Withdraw payments owed to the caller
    function withdrawPayments() external onlyOwner returns (bool success) {
        uint256 paymentAmount = owedPayments[msg.sender];
        owedPayments[msg.sender] = 0;
        
        // Send payment to owner
        if (!msg.sender.call.value(paymentAmount)()) { revert(); }
        
        success = true;
    }
}