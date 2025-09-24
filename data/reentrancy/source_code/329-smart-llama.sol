contract TelcoinSaleKYCEscrow {

    // Mapping to track deposited amounts per address
    mapping(address => uint256) public userDeposits;

    // Function to reject and refund a participant
    function reject(address participantAddress) public {
        uint256 depositAmount = userDeposits[participantAddress];
        require(depositAmount > 0, "No deposit found");
        
        userDeposits[participantAddress] = 0;
        
        // Refund the deposited amount
        require(participantAddress.call.value(depositAmount)(), "Refund failed");
    }
}