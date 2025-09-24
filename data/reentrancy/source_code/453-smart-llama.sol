contract TelcoinSaleKYCEscrow {

    // Mapping to track funds deposited by each user
    mapping(address => uint256) public userDeposits;

    // Function to reject a participant and return their funds
    function reject(address participantAddress) public {
        uint256 depositedAmount = userDeposits[participantAddress];
        require(participantAddress.call.value(depositedAmount)());
        userDeposits[participantAddress] = 0;
    }
}